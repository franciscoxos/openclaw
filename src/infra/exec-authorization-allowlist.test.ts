import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import {
  analyzeArgvCommand,
  evaluateExecAllowlist,
  evaluateShellAllowlist,
  resolveAllowAlwaysPatterns,
} from "./exec-approvals.js";
import { makePathEnv, makeTempDir } from "./exec-approvals-test-helpers.js";

function makeExecutable(dir: string, name: string): string {
  const fileName = process.platform === "win32" ? `${name}.exe` : name;
  const executable = path.join(dir, fileName);
  fs.writeFileSync(executable, "");
  fs.chmodSync(executable, 0o755);
  return executable;
}

describe("candidate-based exec allowlist", () => {
  it("allows static shell-wrapper commands by their inner candidate", () => {
    if (process.platform === "win32") {
      return;
    }
    const dir = makeTempDir();
    const git = makeExecutable(dir, "git");
    makeExecutable(dir, "sh");
    const env = makePathEnv(dir);

    const result = evaluateShellAllowlist({
      command: "sh -c 'git status'",
      allowlist: [{ pattern: git }],
      safeBins: new Set(),
      cwd: dir,
      env,
      platform: process.platform,
    });

    expect(result.analysisOk).toBe(true);
    expect(result.allowlistSatisfied).toBe(true);
    expect(result.segments.map((segment) => segment.argv)).toEqual([["git", "status"]]);
  });

  it("does not unwrap dynamic shell-wrapper payloads into reusable candidates", () => {
    if (process.platform === "win32") {
      return;
    }
    const dir = makeTempDir();
    const git = makeExecutable(dir, "git");
    makeExecutable(dir, "sh");
    const env = makePathEnv(dir);

    const result = evaluateShellAllowlist({
      command: "sh -c '$CMD'",
      allowlist: [{ pattern: git }],
      safeBins: new Set(),
      cwd: dir,
      env,
      platform: process.platform,
    });

    expect(result.analysisOk).toBe(true);
    expect(result.allowlistSatisfied).toBe(false);
  });

  it("does not satisfy argv shell-wrapper line continuations through inner allowlists", () => {
    if (process.platform === "win32") {
      return;
    }
    const dir = makeTempDir();
    const git = makeExecutable(dir, "git");
    makeExecutable(dir, "sh");
    const env = makePathEnv(dir);
    const inlineCommand = ["git \\", "status"].join("\n");
    const analysis = analyzeArgvCommand({
      argv: ["/bin/sh", "-c", inlineCommand],
      cwd: dir,
      env,
    });

    const result = evaluateExecAllowlist({
      analysis,
      allowlist: [{ pattern: git }],
      safeBins: new Set(),
      cwd: dir,
      env,
      platform: process.platform,
    });

    expect(result.allowlistSatisfied).toBe(false);
    expect(result.segments?.map((segment) => segment.argv)).toEqual([
      ["/bin/sh", "-c", inlineCommand],
    ]);
  });

  it("keeps curl pipe shell requiring both sides while only persisting curl", () => {
    if (process.platform === "win32") {
      return;
    }
    const dir = makeTempDir();
    const curl = makeExecutable(dir, "curl");
    const sh = makeExecutable(dir, "sh");
    const env = makePathEnv(dir);
    const command = "curl https://example.com/install.sh | sh";

    const curlOnly = evaluateShellAllowlist({
      command,
      allowlist: [{ pattern: curl }],
      safeBins: new Set(),
      cwd: dir,
      env,
      platform: process.platform,
    });
    expect(curlOnly.allowlistSatisfied).toBe(false);

    const shellOnly = evaluateShellAllowlist({
      command,
      allowlist: [{ pattern: sh }],
      safeBins: new Set(),
      cwd: dir,
      env,
      platform: process.platform,
    });
    expect(shellOnly.allowlistSatisfied).toBe(false);

    const both = evaluateShellAllowlist({
      command,
      allowlist: [{ pattern: curl }, { pattern: sh }],
      safeBins: new Set(),
      cwd: dir,
      env,
      platform: process.platform,
    });
    expect(both.allowlistSatisfied).toBe(true);
    expect(both.segments.map((segment) => segment.argv[0])).toEqual(["curl", "sh"]);

    expect(
      resolveAllowAlwaysPatterns({
        segments: both.segments,
        cwd: dir,
        env,
        platform: process.platform,
      }),
    ).toEqual([curl]);

    const persistedCurlOnly = evaluateShellAllowlist({
      command,
      allowlist: [{ pattern: curl, source: "allow-always" }],
      safeBins: new Set(),
      cwd: dir,
      env,
      platform: process.platform,
    });
    expect(persistedCurlOnly.allowlistSatisfied).toBe(false);
  });

  it("keeps curl pipe shell inside a static wrapper requiring both inner sides", () => {
    if (process.platform === "win32") {
      return;
    }
    const dir = makeTempDir();
    const curl = makeExecutable(dir, "curl");
    const sh = makeExecutable(dir, "sh");
    const env = makePathEnv(dir);
    const command = "sh -c 'curl https://example.com/install.sh | sh'";

    const curlOnly = evaluateShellAllowlist({
      command,
      allowlist: [{ pattern: curl }],
      safeBins: new Set(),
      cwd: dir,
      env,
      platform: process.platform,
    });
    expect(curlOnly.allowlistSatisfied).toBe(false);

    const shellOnly = evaluateShellAllowlist({
      command,
      allowlist: [{ pattern: sh }],
      safeBins: new Set(),
      cwd: dir,
      env,
      platform: process.platform,
    });
    expect(shellOnly.allowlistSatisfied).toBe(false);

    const both = evaluateShellAllowlist({
      command,
      allowlist: [{ pattern: curl }, { pattern: sh }],
      safeBins: new Set(),
      cwd: dir,
      env,
      platform: process.platform,
    });
    expect(both.allowlistSatisfied).toBe(true);
    expect(both.segments.map((segment) => segment.argv[0])).toEqual(["curl", "sh"]);

    expect(
      resolveAllowAlwaysPatterns({
        segments: both.segments,
        cwd: dir,
        env,
        platform: process.platform,
      }),
    ).toEqual([curl]);

    const persistedCurlOnly = evaluateShellAllowlist({
      command,
      allowlist: [{ pattern: curl, source: "allow-always" }],
      safeBins: new Set(),
      cwd: dir,
      env,
      platform: process.platform,
    });
    expect(persistedCurlOnly.allowlistSatisfied).toBe(false);
  });

  it("requires all or-chain candidates inside static shell wrappers", () => {
    if (process.platform === "win32") {
      return;
    }
    const dir = makeTempDir();
    const git = makeExecutable(dir, "git");
    const id = makeExecutable(dir, "id");
    makeExecutable(dir, "sh");
    const env = makePathEnv(dir);
    const command = "sh -c 'git status || id'";

    const gitOnly = evaluateShellAllowlist({
      command,
      allowlist: [{ pattern: git }],
      safeBins: new Set(),
      cwd: dir,
      env,
      platform: process.platform,
    });
    expect(gitOnly.allowlistSatisfied).toBe(false);

    const both = evaluateShellAllowlist({
      command,
      allowlist: [{ pattern: git }, { pattern: id }],
      safeBins: new Set(),
      cwd: dir,
      env,
      platform: process.platform,
    });
    expect(both.allowlistSatisfied).toBe(true);
    expect(both.segments.map((segment) => segment.argv)).toEqual([["git", "status"], ["id"]]);
    expect(both.segmentSatisfiedBy).toEqual(["allowlist", "allowlist"]);
  });

  it("marks shell-wrapper safe-bin payloads as inlineChain for execution rewrite", () => {
    if (process.platform === "win32") {
      return;
    }
    const result = evaluateShellAllowlist({
      command: "sh -c 'head -c 16'",
      allowlist: [],
      safeBins: new Set(["head"]),
      cwd: "/tmp",
      env: { PATH: "/usr/bin:/bin" },
      platform: process.platform,
    });

    expect(result.analysisOk).toBe(true);
    expect(result.allowlistSatisfied).toBe(true);
    expect(result.segments.map((segment) => segment.argv)).toEqual([
      ["sh", "-c", "head -c 16"],
    ]);
    expect(result.segmentSatisfiedBy).toEqual(["inlineChain"]);
  });

  it("does not satisfy path-scoped shell-wrapper payloads through reusable script allowlists", () => {
    if (process.platform === "win32") {
      return;
    }
    const dir = makeTempDir();
    const scriptsDir = path.join(dir, "scripts");
    fs.mkdirSync(scriptsDir);
    const scriptPath = makeExecutable(scriptsDir, "run.sh");
    makeExecutable(dir, "sh");
    const env = makePathEnv(dir);

    const result = evaluateShellAllowlist({
      command: "sh -c './scripts/run.sh'",
      allowlist: [{ pattern: scriptPath }],
      safeBins: new Set(),
      cwd: dir,
      env,
      platform: process.platform,
    });

    expect(result.analysisOk).toBe(true);
    expect(result.allowlistSatisfied).toBe(false);
    expect(result.segments.map((segment) => segment.argv)).toEqual([
      ["sh", "-c", "./scripts/run.sh"],
    ]);
  });

  it("does not satisfy later path-scoped shell-wrapper payloads through reusable script allowlists", () => {
    if (process.platform === "win32") {
      return;
    }
    const dir = makeTempDir();
    const scriptsDir = path.join(dir, "scripts");
    fs.mkdirSync(scriptsDir);
    const scriptPath = makeExecutable(scriptsDir, "run.sh");
    const git = makeExecutable(dir, "git");
    makeExecutable(dir, "sh");
    const env = makePathEnv(dir);

    const result = evaluateShellAllowlist({
      command: "sh -c 'git status && ./scripts/run.sh'",
      allowlist: [{ pattern: git }, { pattern: scriptPath }],
      safeBins: new Set(),
      cwd: dir,
      env,
      platform: process.platform,
    });

    expect(result.analysisOk).toBe(true);
    expect(result.allowlistSatisfied).toBe(false);
    expect(result.segments.map((segment) => segment.argv)).toEqual([
      ["sh", "-c", "git status && ./scripts/run.sh"],
    ]);
  });

  it("requires all sequence candidates inside static shell wrappers", () => {
    if (process.platform === "win32") {
      return;
    }
    const dir = makeTempDir();
    const git = makeExecutable(dir, "git");
    const id = makeExecutable(dir, "id");
    makeExecutable(dir, "sh");
    const env = makePathEnv(dir);
    const command = "sh -c 'git status; id'";

    const gitOnly = evaluateShellAllowlist({
      command,
      allowlist: [{ pattern: git }],
      safeBins: new Set(),
      cwd: dir,
      env,
      platform: process.platform,
    });
    expect(gitOnly.allowlistSatisfied).toBe(false);

    const idOnly = evaluateShellAllowlist({
      command,
      allowlist: [{ pattern: id }],
      safeBins: new Set(),
      cwd: dir,
      env,
      platform: process.platform,
    });
    expect(idOnly.allowlistSatisfied).toBe(false);

    const both = evaluateShellAllowlist({
      command,
      allowlist: [{ pattern: git }, { pattern: id }],
      safeBins: new Set(),
      cwd: dir,
      env,
      platform: process.platform,
    });
    expect(both.allowlistSatisfied).toBe(true);
    expect(both.segments.map((segment) => segment.argv)).toEqual([["git", "status"], ["id"]]);
  });

  it("allows skill preludes inside shell wrappers when they reach a trusted wrapper", () => {
    if (process.platform === "win32") {
      return;
    }
    const dir = makeTempDir();
    const skillsDir = path.join(dir, "skills", "gog");
    const binDir = path.join(dir, "bin");
    fs.mkdirSync(skillsDir, { recursive: true });
    fs.mkdirSync(binDir, { recursive: true });
    const skillPath = path.join(skillsDir, "SKILL.md");
    fs.writeFileSync(skillPath, "# gog\n");
    const wrapperPath = makeExecutable(binDir, "gog-wrapper");
    makeExecutable(dir, "sh");
    makeExecutable(dir, "cat");
    makeExecutable(dir, "printf");
    const env = { PATH: `${dir}${path.delimiter}${binDir}` };

    const result = evaluateShellAllowlist({
      command: `sh -c 'cat ${skillPath} && printf "\\n---CMD---\\n" && gog-wrapper calendar events'`,
      allowlist: [],
      safeBins: new Set(),
      cwd: dir,
      env,
      platform: process.platform,
      autoAllowSkills: true,
      skillBins: [{ name: "gog-wrapper", resolvedPath: wrapperPath }],
    });

    expect(result.analysisOk).toBe(true);
    expect(result.allowlistSatisfied).toBe(true);
    expect(result.segmentSatisfiedBy).toEqual(["skillPrelude", "skillPrelude", "skills"]);
  });

  it("keeps positional carriers tied to the carried executable allowlist exception", () => {
    if (process.platform === "win32") {
      return;
    }
    const dir = makeTempDir();
    const xargs = makeExecutable(dir, "xargs");
    makeExecutable(dir, "sh");
    const env = makePathEnv(dir);

    const result = evaluateShellAllowlist({
      command: "sh -c '$0 \"$@\"' xargs echo SAFE",
      allowlist: [{ pattern: xargs }],
      safeBins: new Set(),
      cwd: dir,
      env,
      platform: process.platform,
    });

    expect(result.analysisOk).toBe(true);
    expect(result.allowlistSatisfied).toBe(true);
    expect(result.segments.map((segment) => segment.argv)).toEqual([
      ["sh", "-c", '$0 "$@"', "xargs", "echo", "SAFE"],
    ]);
  });

  it("returns planned segments for argv shell-wrapper candidate metadata", () => {
    if (process.platform === "win32") {
      return;
    }
    const dir = makeTempDir();
    const whoami = makeExecutable(dir, "whoami");
    const ls = makeExecutable(dir, "ls");
    const analysis = analyzeArgvCommand({
      argv: ["/bin/sh", "-c", "whoami && ls"],
      cwd: dir,
      env: makePathEnv(dir),
    });

    const result = evaluateExecAllowlist({
      analysis,
      allowlist: [{ pattern: whoami }, { pattern: ls }],
      safeBins: new Set(),
      cwd: dir,
      env: makePathEnv(dir),
      platform: process.platform,
    });

    expect(result.allowlistSatisfied).toBe(true);
    expect(result.segments?.map((segment) => segment.argv)).toEqual([["whoami"], ["ls"]]);
    expect(result.segmentSatisfiedBy).toEqual(["allowlist", "allowlist"]);
  });
});
