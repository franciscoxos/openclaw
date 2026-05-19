import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  emitDiagnosticEvent,
  resetDiagnosticEventsForTest,
} from "./diagnostic-events";
import {
  getRegisteredSessionForTest,
  registerSessionProcess,
  startSessionSupervisor,
  stopSessionSupervisorForTest,
  unregisterSessionProcess,
} from "./session-supervisor";

describe("session-supervisor", () => {
  beforeEach(() => {
    resetDiagnosticEventsForTest();
    stopSessionSupervisorForTest();
    process.env.OPENCLAW_SESSION_SUPERVISOR = "1";
  });

  afterEach(() => {
    stopSessionSupervisorForTest();
    delete process.env.OPENCLAW_SESSION_SUPERVISOR;
  });

  it("does nothing when the env opt-in is not set", () => {
    delete process.env.OPENCLAW_SESSION_SUPERVISOR;
    const stop = startSessionSupervisor();
    expect(typeof stop).toBe("function");
    // No registry interaction should happen.
  });

  it("registers and unregisters processes", () => {
    registerSessionProcess("agent:main:session-1", 12345, () => {});
    expect(getRegisteredSessionForTest("agent:main:session-1")?.pgid).toBe(12345);
    unregisterSessionProcess("agent:main:session-1");
    expect(getRegisteredSessionForTest("agent:main:session-1")).toBeUndefined();
  });

  it("ignores invalid pgid", () => {
    registerSessionProcess("k", 0);
    registerSessionProcess("k2", -5);
    expect(getRegisteredSessionForTest("k")).toBeUndefined();
    expect(getRegisteredSessionForTest("k2")).toBeUndefined();
  });

  it("no-op when session.stuck arrives for unregistered sessionKey", () => {
    const killSpy = vi.spyOn(process, "kill").mockImplementation(() => true);
    startSessionSupervisor();
    emitDiagnosticEvent({
      type: "session.stuck",
      sessionKey: "unknown:session",
      sessionId: "sid",
      state: "stale",
      classification: "stale_session_state",
      ageMs: 60000,
      stateGeneration: 1,
    } as never);
    // Allow microtask drain
    return Promise.resolve().then(() => {
      expect(killSpy).not.toHaveBeenCalled();
      killSpy.mockRestore();
    });
  });

  // Note: full integration (real pgroup kill + cleanup hook + recovery event)
  // requires a child-process harness — covered by e2e in src/infra/restart.* tests
  // pattern (TODO follow-up).
});
