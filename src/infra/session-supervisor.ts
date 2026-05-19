// Session supervisor — subscribes to `session.stuck` diagnostic events and
// performs SIGKILL on the tracked process group + native session-store cleanup.
//
// Goal: bound recovery time when a session reaches `stale_session_state`
// classification. Today emitting `session.stuck` only logs; downstream tooling
// (cron-supervisor wrappers, watchdog crons, observability) have to react out
// of band, which means stuck sessions can pile up between heartbeats.
//
// Contract:
//   - Subscribe via `onInternalDiagnosticEvent` (we need trusted events too).
//   - On `session.stuck`, look up the pid (process group leader) registered for
//     `sessionKey` via the supervisor's registry (populated by callers when they
//     spawn a session-owning child process). If unregistered, no-op.
//   - SIGKILL the pgid (`process.kill(-pgid, "SIGKILL")` on POSIX), then call
//     the registered cleanup hook so the native session-store releases locks.
//   - Telemetry: emit a trusted `session.recovery` event with status
//     `released` on success, `failed` with reason on error.
//   - Disabled by default in test (gated by env `OPENCLAW_SESSION_SUPERVISOR=1`).
//
// Caller responsibilities:
//   - Call `registerSessionProcess(sessionKey, pgid, cleanup)` when a
//     session-owning child process is spawned.
//   - Call `unregisterSessionProcess(sessionKey)` when the process exits cleanly.
//
// Not in scope:
//   - Cross-host pgroup cleanup (single-host only).
//   - Windows pgroup semantics (Win32 fallback: SIGTERM the pid only).
//
// See also: src/infra/diagnostic-events.ts (event types),
//           src/infra/gateway-processes.ts (pattern for `process.kill`).

import {
  emitTrustedDiagnosticEvent,
  onInternalDiagnosticEvent,
} from "./diagnostic-events";

const SUPERVISOR_ENV = "OPENCLAW_SESSION_SUPERVISOR";

interface RegisteredSession {
  pgid: number;
  cleanup?: () => void | Promise<void>;
}

const REGISTRY = new Map<string, RegisteredSession>();
let UNSUBSCRIBE: (() => void) | null = null;

export function registerSessionProcess(
  sessionKey: string,
  pgid: number,
  cleanup?: () => void | Promise<void>,
): void {
  if (!sessionKey || !Number.isFinite(pgid) || pgid <= 0) {
    return;
  }
  REGISTRY.set(sessionKey, { pgid, cleanup });
}

export function unregisterSessionProcess(sessionKey: string): void {
  REGISTRY.delete(sessionKey);
}

export function getRegisteredSessionForTest(
  sessionKey: string,
): RegisteredSession | undefined {
  return REGISTRY.get(sessionKey);
}

function killProcessGroup(pgid: number): "killed" | "no_process" | "error" {
  if (process.platform === "win32") {
    // Win32 has no pgroup semantics here; supervisor is a best-effort POSIX feature.
    try {
      process.kill(pgid, "SIGTERM");
      return "killed";
    } catch (e) {
      const code = (e as NodeJS.ErrnoException).code;
      if (code === "ESRCH") return "no_process";
      return "error";
    }
  }
  try {
    process.kill(-pgid, "SIGKILL");
    return "killed";
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code;
    if (code === "ESRCH") return "no_process";
    return "error";
  }
}

async function runCleanupSafe(
  cleanup: (() => void | Promise<void>) | undefined,
): Promise<{ ok: boolean; error?: string }> {
  if (!cleanup) return { ok: true };
  try {
    await cleanup();
    return { ok: true };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : String(e) };
  }
}

async function handleSessionStuck(event: {
  sessionKey?: string;
  sessionId?: string;
  ageMs?: number;
  state?: string;
}): Promise<void> {
  const key = event.sessionKey;
  if (!key) return;
  const reg = REGISTRY.get(key);
  if (!reg) {
    // Not owned by this process — nothing to do.
    return;
  }
  const killResult = killProcessGroup(reg.pgid);
  const cleanupResult = await runCleanupSafe(reg.cleanup);
  REGISTRY.delete(key);

  // Emit recovery event so observers (cron-supervisor wrappers, monitor) see it.
  emitTrustedDiagnosticEvent({
    type: "session.recovery",
    sessionKey: key,
    sessionId: event.sessionId,
    state: (event.state as never) ?? "unknown",
    ageMs: event.ageMs ?? 0,
    status:
      killResult === "killed" && cleanupResult.ok
        ? "released"
        : killResult === "no_process"
          ? "skipped"
          : "failed",
    reason:
      killResult === "error"
        ? "kill_failed"
        : cleanupResult.ok
          ? undefined
          : `cleanup_error:${cleanupResult.error}`,
  } as never);
}

export function startSessionSupervisor(): () => void {
  if (UNSUBSCRIBE) {
    return UNSUBSCRIBE;
  }
  if (process.env[SUPERVISOR_ENV] !== "1") {
    // Disabled unless opt-in. Returns no-op stop handle.
    return () => {};
  }
  UNSUBSCRIBE = onInternalDiagnosticEvent((event) => {
    if (event.type !== "session.stuck") return;
    void handleSessionStuck(event);
  });
  return () => {
    if (UNSUBSCRIBE) {
      UNSUBSCRIBE();
      UNSUBSCRIBE = null;
    }
  };
}

export function stopSessionSupervisorForTest(): void {
  if (UNSUBSCRIBE) {
    UNSUBSCRIBE();
    UNSUBSCRIBE = null;
  }
  REGISTRY.clear();
}
