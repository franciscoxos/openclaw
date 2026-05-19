import {
  analyzeShellCommand,
  splitCommandChainWithOperators,
  type ExecCommandAnalysis,
  type ExecCommandSegment,
  type ShellChainOperator,
} from "./exec-approvals-analysis.js";
import {
  extractBindableShellWrapperInlineCommand,
  normalizeExecutableToken,
} from "./exec-wrapper-resolution.js";

export type ExecAuthorizationRelationship =
  | "simple"
  | "pipeline"
  | "sequence"
  | "and"
  | "or"
  | "wrapper-inline";

export type ExecAuthorizationTransport =
  | { kind: "direct" }
  | {
      kind: "shell-wrapper";
      wrapperSegment: ExecCommandSegment;
      wrapperArgv: string[];
      inlineCommand: string;
    };

export type ExecAuthorizationTrustMode = "executable" | "exact-command" | "prompt-only";

export type ExecAuthorizationCandidate = {
  argv: string[];
  sourceSegment: ExecCommandSegment;
  relationship: ExecAuthorizationRelationship;
  transport: ExecAuthorizationTransport;
  trustMode: ExecAuthorizationTrustMode;
};

export type ExecAuthorizationGroup = {
  relationship: ExecAuthorizationRelationship;
  opFromPrevious?: ShellChainOperator | null;
  opToNext?: ShellChainOperator | null;
  candidates: ExecAuthorizationCandidate[];
};

export type ExecAuthorizationPlan =
  | {
      ok: true;
      originalCommand: string;
      groups: ExecAuthorizationGroup[];
      executionSegments: ExecCommandSegment[];
    }
  | {
      ok: false;
      originalCommand: string;
      reason: string;
      groups: [];
      executionSegments: [];
    };

type PlanSource = {
  command: string;
  analysis: ExecCommandAnalysis;
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  platform?: string | null;
};

function hasDynamicInlinePayload(command: string): boolean {
  return /[$`]/.test(command) || /\\(?:\r\n|\n|\r)/.test(command);
}

function isPathScopedExecutableToken(token: string): boolean {
  return token.includes("/") || token.includes("\\");
}

export function canUseReusableWrapperPayloadCandidates(
  segments: readonly ExecCommandSegment[],
): boolean {
  const firstExecutable = segments[0]?.argv[0]?.trim() ?? "";
  if (!firstExecutable) {
    return false;
  }
  if (segments.some((segment) => isPathScopedExecutableToken(segment.argv[0]?.trim() ?? ""))) {
    return false;
  }
  return !normalizeExecutableToken(firstExecutable).endsWith("-wrapper");
}

function relationshipForOperator(
  operator: ShellChainOperator | null | undefined,
): ExecAuthorizationRelationship {
  if (operator === "&&") {
    return "and";
  }
  if (operator === "||") {
    return "or";
  }
  if (operator === ";") {
    return "sequence";
  }
  return "simple";
}

function createCandidate(params: {
  segment: ExecCommandSegment;
  relationship: ExecAuthorizationRelationship;
  transport: ExecAuthorizationTransport;
}): ExecAuthorizationCandidate {
  return {
    argv: params.segment.argv,
    sourceSegment: params.segment,
    relationship: params.relationship,
    transport: params.transport,
    trustMode: resolveCandidateTrustMode(params.segment, params.transport),
  };
}

function resolveCandidateTrustMode(
  segment: ExecCommandSegment,
  transport: ExecAuthorizationTransport,
): ExecAuthorizationTrustMode {
  if (segment.resolution?.policyBlocked === true) {
    return "prompt-only";
  }
  if (transport.kind === "direct" && extractBindableShellWrapperInlineCommand(segment.argv)) {
    return "exact-command";
  }
  return "executable";
}

function directGroup(params: {
  segments: ExecCommandSegment[];
  relationship: ExecAuthorizationRelationship;
  transport: ExecAuthorizationTransport;
}): ExecAuthorizationGroup {
  const relationship =
    params.segments.length > 1 && params.relationship === "simple"
      ? "pipeline"
      : params.relationship;
  return {
    relationship,
    candidates: params.segments.map((segment) =>
      createCandidate({
        segment,
        relationship,
        transport: params.transport,
      }),
    ),
  };
}

function wrapperPayloadGroups(params: {
  segment: ExecCommandSegment;
  inlineCommand: string;
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  platform?: string | null;
}): ExecAuthorizationGroup[] | null {
  if (hasDynamicInlinePayload(params.inlineCommand)) {
    return null;
  }
  const nested = analyzeShellCommand({
    command: params.inlineCommand,
    cwd: params.cwd,
    env: params.env,
    platform: params.platform,
  });
  if (!nested.ok || nested.segments.length === 0) {
    return null;
  }
  if (!canUseReusableWrapperPayloadCandidates(nested.segments)) {
    return null;
  }
  const transport: ExecAuthorizationTransport = {
    kind: "shell-wrapper",
    wrapperSegment: params.segment,
    wrapperArgv: params.segment.argv,
    inlineCommand: params.inlineCommand,
  };
  const groups = groupsFromAnalysis({
    command: params.inlineCommand,
    analysis: nested,
    transport,
    cwd: params.cwd,
    env: params.env,
    platform: params.platform,
  });
  return groups.length > 0 ? groups : null;
}

function groupsFromSegments(params: {
  segments: ExecCommandSegment[];
  relationship: ExecAuthorizationRelationship;
  transport: ExecAuthorizationTransport;
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  platform?: string | null;
}): ExecAuthorizationGroup[] {
  const groups: ExecAuthorizationGroup[] = [];
  if (params.transport.kind === "direct" && params.segments.length === 1) {
    const segment = params.segments[0];
    if (segment && segment.resolution?.policyBlocked !== true) {
      const inlineCommand = extractBindableShellWrapperInlineCommand(segment.argv);
      if (inlineCommand) {
        const nestedGroups = wrapperPayloadGroups({
          segment,
          inlineCommand,
          cwd: params.cwd,
          env: params.env,
          platform: params.platform,
        });
        if (nestedGroups) {
          return nestedGroups;
        }
      }
    }
  }

  groups.push(
    directGroup({
      segments: params.segments,
      relationship: params.relationship,
      transport: params.transport,
    }),
  );
  return groups;
}

function groupsFromAnalysis(params: {
  command: string;
  analysis: ExecCommandAnalysis;
  transport: ExecAuthorizationTransport;
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  platform?: string | null;
}): ExecAuthorizationGroup[] {
  const chainParts = splitCommandChainWithOperators(params.command);
  if (!chainParts) {
    return groupsFromSegments({
      segments: params.analysis.segments,
      relationship: params.analysis.segments.length > 1 ? "pipeline" : "simple",
      transport: params.transport,
      cwd: params.cwd,
      env: params.env,
      platform: params.platform,
    });
  }

  const groups: ExecAuthorizationGroup[] = [];
  for (let index = 0; index < chainParts.length; index += 1) {
    const part = chainParts[index];
    if (!part) {
      continue;
    }
    const partAnalysis = analyzeShellCommand({
      command: part.part,
      cwd: params.cwd,
      env: params.env,
      platform: params.platform,
    });
    if (!partAnalysis.ok) {
      return [];
    }
    const previousOperator = index === 0 ? null : chainParts[index - 1]?.opToNext;
    const partGroups = groupsFromSegments({
      segments: partAnalysis.segments,
      relationship: relationshipForOperator(previousOperator),
      transport: params.transport,
      cwd: params.cwd,
      env: params.env,
      platform: params.platform,
    });
    for (let groupIndex = 0; groupIndex < partGroups.length; groupIndex += 1) {
      const group = partGroups[groupIndex];
      if (!group) {
        continue;
      }
      groups.push({
        ...group,
        opFromPrevious: groupIndex === 0 ? previousOperator : group.opFromPrevious,
        opToNext: groupIndex === partGroups.length - 1 ? part.opToNext : group.opToNext,
      });
    }
  }
  return groups;
}

function planFromAnalysis(source: PlanSource): ExecAuthorizationPlan {
  if (!source.analysis.ok) {
    return {
      ok: false,
      originalCommand: source.command,
      reason: source.analysis.reason ?? "unable to parse command",
      groups: [],
      executionSegments: [],
    };
  }

  const groups = groupsFromAnalysis({
    command: source.command,
    analysis: source.analysis,
    transport: { kind: "direct" },
    cwd: source.cwd,
    env: source.env,
    platform: source.platform,
  });
  if (groups.length === 0) {
    return {
      ok: false,
      originalCommand: source.command,
      reason: "unable to plan command authorization",
      groups: [],
      executionSegments: [],
    };
  }
  return {
    ok: true,
    originalCommand: source.command,
    groups,
    executionSegments: source.analysis.segments,
  };
}

export function planShellAuthorization(params: {
  command: string;
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  platform?: string | null;
}): ExecAuthorizationPlan {
  return planFromAnalysis({
    command: params.command,
    analysis: analyzeShellCommand({
      command: params.command,
      cwd: params.cwd,
      env: params.env,
      platform: params.platform,
    }),
    cwd: params.cwd,
    env: params.env,
    platform: params.platform,
  });
}

export function planExecAuthorization(params: {
  analysis: ExecCommandAnalysis;
  command?: string;
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  platform?: string | null;
}): ExecAuthorizationPlan {
  const command =
    params.command ??
    params.analysis.segments
      .map((segment) => segment.raw)
      .join(params.analysis.chains ? " && " : " | ");
  if (!params.analysis.ok) {
    return {
      ok: false,
      originalCommand: command,
      reason: params.analysis.reason ?? "unable to parse command",
      groups: [],
      executionSegments: [],
    };
  }
  const groups = groupsFromSegments({
    segments: params.analysis.segments,
    relationship: params.analysis.segments.length > 1 ? "pipeline" : "simple",
    transport: { kind: "direct" },
    cwd: params.cwd,
    env: params.env,
    platform: params.platform,
  });
  return {
    ok: true,
    originalCommand: command,
    groups,
    executionSegments: params.analysis.segments,
  };
}
