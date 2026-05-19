import path from "node:path";
import {
  readRootJsonObjectSync as rawReadRootJsonObjectSync,
  tryReadJsonSync as rawTryReadJsonSync,
  writeJsonSync as rawWriteJsonSync,
} from "@openclaw/fs-safe/json";
import "./fs-safe-defaults.js";
import { replaceFileAtomic } from "./replace-file.js";

// Process-scoped memo for synchronous JSON reads. The TUI startup path (and a
// few discovery flows) re-read the same plugin manifests hundreds of times
// each; caching parsed values keyed by absolute path keeps memory cost tiny
// (~one entry per unique file) while eliminating the repeated open + parse.
// Disable with OPENCLAW_DISABLE_JSON_READ_CACHE=1 for tests that mutate JSON
// files mid-process and need to observe fresh state.
type CacheEntry = { value: unknown };
const jsonReadCache = new Map<string, CacheEntry>();

function isJsonReadCacheDisabled(): boolean {
  return process.env.OPENCLAW_DISABLE_JSON_READ_CACHE === "1";
}

function jsonReadCacheKey(filePath: string): string {
  return path.resolve(filePath);
}

function getCachedJsonRead(filePath: string): { hit: true; value: unknown } | { hit: false } {
  if (isJsonReadCacheDisabled()) {
    return { hit: false };
  }
  const entry = jsonReadCache.get(jsonReadCacheKey(filePath));
  return entry ? { hit: true, value: entry.value } : { hit: false };
}

function setCachedJsonRead(filePath: string, value: unknown): void {
  if (isJsonReadCacheDisabled()) {
    return;
  }
  jsonReadCache.set(jsonReadCacheKey(filePath), { value });
}

function invalidateCachedJsonRead(filePath: string): void {
  jsonReadCache.delete(jsonReadCacheKey(filePath));
}

/** Clear all memoized sync-JSON reads. */
export function clearJsonReadCache(): void {
  jsonReadCache.clear();
}

export const tryReadJsonSync = ((...args: unknown[]) => {
  const filePath = args[0];
  if (typeof filePath === "string") {
    const cached = getCachedJsonRead(filePath);
    if (cached.hit) {
      return cached.value;
    }
    const result = (rawTryReadJsonSync as (...a: unknown[]) => unknown)(...args);
    if (result !== null && result !== undefined) {
      setCachedJsonRead(filePath, result);
    }
    return result;
  }
  return (rawTryReadJsonSync as (...a: unknown[]) => unknown)(...args);
}) as typeof rawTryReadJsonSync;
export const readJsonFileSync = tryReadJsonSync;

export const readRootJsonObjectSync = ((...args: unknown[]) => {
  const params = args[0];
  if (params && typeof params === "object") {
    const rootDir = (params as { rootDir?: unknown }).rootDir;
    const relativePath = (params as { relativePath?: unknown }).relativePath;
    if (typeof rootDir === "string" && typeof relativePath === "string") {
      const filePath = path.join(rootDir, relativePath);
      const cached = getCachedJsonRead(filePath);
      if (cached.hit) {
        return cached.value;
      }
      const result = (rawReadRootJsonObjectSync as (...a: unknown[]) => unknown)(...args);
      if (result && typeof result === "object" && (result as { ok?: unknown }).ok === true) {
        setCachedJsonRead(filePath, result);
      }
      return result;
    }
  }
  return (rawReadRootJsonObjectSync as (...a: unknown[]) => unknown)(...args);
}) as typeof rawReadRootJsonObjectSync;

// Sync write paths invalidate any cached read for the same path so callers
// that immediately re-read after writing observe their own change.
function invalidateWriteTarget(target: unknown): void {
  if (typeof target === "string") {
    invalidateCachedJsonRead(target);
  }
}

export const writeJsonSync = ((...args: unknown[]) => {
  invalidateWriteTarget(args[0]);
  return (rawWriteJsonSync as (...a: unknown[]) => unknown)(...args);
}) as typeof rawWriteJsonSync;

export {
  JsonFileReadError,
  readJson,
  readJson as readJsonFileStrict,
  readJsonIfExists,
  readJsonIfExists as readDurableJsonFile,
  readJsonSync,
  readRootJsonSync,
  readRootStructuredFileSync,
  tryReadJson,
  tryReadJson as readJsonFile,
  writeJson,
  writeJson as writeJsonAtomic,
} from "@openclaw/fs-safe/json";
export { createAsyncLock } from "@openclaw/fs-safe/advanced";

export type WriteTextAtomicOptions = {
  mode?: number;
  dirMode?: number;
  trailingNewline?: boolean;
  durable?: boolean;
};

export async function writeTextAtomic(
  filePath: string,
  content: string,
  options?: WriteTextAtomicOptions,
): Promise<void> {
  const payload = options?.trailingNewline && !content.endsWith("\n") ? `${content}\n` : content;
  await replaceFileAtomic({
    filePath,
    content: payload,
    mode: options?.mode ?? 0o600,
    dirMode: options?.dirMode ?? 0o777 & ~process.umask(),
    copyFallbackOnPermissionError: true,
    syncTempFile: options?.durable !== false,
    syncParentDir: options?.durable !== false,
  });
}
