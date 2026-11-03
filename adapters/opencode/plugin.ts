import { readFileSync } from "node:fs";
import { dirname, isAbsolute, resolve } from "node:path";
import type { Plugin, Skill } from "@opencode/plugin";
import type { PermissionEvaluation } from "@opencode/plugin/promise/permission";
import type { Registration } from "@opencode/plugin/promise/registration";
import type { ToolContext } from "@opencode/plugin/promise/tool";
import bloodhoundSource from "../../agents/bloodhound.md" with { type: "text" };
import refactorChallengerSource from "../../agents/refactor-challenger.md" with { type: "text" };
import { readAnalyzerArtifact } from "../../src/core/analyzer-artifact-registry.ts";
import { installConfirmationText, intakeConfirmationText, saveConfirmationText } from "../../src/core/confirmation-text.ts";
import { runSniffAnalyzer, runSniffInstall, type SniffInstallMode, type SniffInstallResult, sniffInstallAuthorizationRequest } from "../../src/core/install.ts";
import type { CanonicalConfirmationRequest, IntakeAuthorization, IntakeInput } from "../../src/core/intake.ts";
import { intakeInput, publicSniffIntakeResult, runSniffIntakeTool } from "../../src/core/intake-use-case.ts";
import { analyzerArtifactPage, analyzerPageLimit, analyzerProjection, MAX_MODEL_CONTENT_BYTES, publicPreflight, reportArtifactPage, reportRenderContent, utf8Prefix } from "../../src/core/model-content.ts";
import type { ReportInput } from "../../src/core/report.ts";
import { readReportArtifact } from "../../src/core/report-artifact-registry.ts";
import { runSniffReportTool, type SniffReportMode } from "../../src/core/report-use-case.ts";
import { cancelRunLease, type RunLeaseReceipt, readRunManifest } from "../../src/core/run-registry.ts";
import type { TargetRequest } from "../../src/core/target.ts";
import { sniffToolInputSchemas } from "../../src/core/tool-schemas.ts";

export const SNIFF_PLUGIN_ID = "srobroek.sniff";

/**
 * Permission actions for the three trusted Sniff approvals. They differ from the tool names so a
 * rule for a gate never matches the tool call itself; `sniff_confirm_*` covers all three.
 */
export const CONFIRM_ACTIONS = {
  intake: "sniff_confirm_intake",
  install: "sniff_confirm_install",
  save: "sniff_confirm_save",
} as const;

const CONFIRM_ACTION_NAMES: ReadonlySet<string> = new Set(Object.values(CONFIRM_ACTIONS));
const MODEL_ROLE_HEADER = "x-opencode-model-role";
const APPROVAL_ACTOR = "opencode-permission";
const APPROVAL_REASON = "Approved through the OpenCode permission prompt.";
const MAX_PROMPT_FILES = 200;
const INSTALL_MODES: ReadonlySet<string> = new Set(["probe", "diagnose", "list", "install"]);

type ToolResult = { readonly content: string; readonly metadata?: Record<string, unknown> };

export type SniffOpenCodeOptions = {
  /** Absolute path of the OpenCode-flavoured `skills/sniff/SKILL.md` shipped beside the bundle. */
  readonly skillPath: string;
};

/** `path` as an absolute path, resolving a relative one against the session's directory. */
export function anchorPath(path: string, base: string): string {
  return isAbsolute(path) ? path : resolve(base, path);
}

// The remote forms the core accepts (validateRepository): `git@host:path` or a URL with a scheme.
const REMOTE_LOCATOR = /^(?:git@[^:/\s]+:|[A-Za-z][A-Za-z0-9+.-]*:\/\/)/;

function anchorLocator(value: string, base: string): string {
  return REMOTE_LOCATOR.test(value.trim()) ? value : anchorPath(value, base);
}

/**
 * The target with every local path anchored to `base`. The OpenCode server is shared across
 * projects, so its process cwd never identifies the session's project. A `repository` or
 * `rootOrRepository` in a remote form stays as written; anything else is a local path and is
 * anchored even when it does not exist, so resolution fails instead of finding a server-side path.
 */
export function anchorTarget(target: TargetRequest, base: string): TargetRequest {
  const record: Record<string, unknown> = { ...target };
  if (typeof record.root === "string") record.root = anchorPath(record.root, base);
  if (typeof record.rootOrRepository === "string") record.rootOrRepository = anchorLocator(record.rootOrRepository, base);
  if (typeof record.repository === "string") record.repository = anchorLocator(record.repository, base);
  return record as TargetRequest;
}

/**
 * Permission `evaluate` hook: label each Sniff approval with its plan text and, when
 * `confirm` is on, turn an `allow` into `ask`. OpenCode's default policy allows every action,
 * so without the escalation a plan, install, or save would pass without a person seeing it.
 * A configured `deny` never reaches the hook.
 */
export function confirmSniffApproval(evaluation: Pick<PermissionEvaluation, "action" | "metadata"> & { effect: string; message?: string }, confirm = true): void {
  if (!CONFIRM_ACTION_NAMES.has(evaluation.action)) return;
  if (confirm && evaluation.effect === "allow") evaluation.effect = "ask";
  const summary = evaluation.metadata?.summary;
  if (typeof summary === "string") evaluation.message = summary;
}

type AgentDefinition = {
  readonly id: string;
  readonly description: string;
  readonly system: string;
  readonly tier: string;
};

const FRONTMATTER = /^---\r?\n([\s\S]*?)\r?\n---\r?\n?/;

function unquote(value: string): string {
  const trimmed = value.trim();
  const first = trimmed[0];
  if (trimmed.length > 1 && (first === '"' || first === "'") && trimmed.endsWith(first)) return trimmed.slice(1, -1);
  return trimmed;
}

/** The description and system prompt of a shipped `agents/<id>.md`. The OpenCode tier replaces its OMP `model` field. */
export function parseAgentSource(id: string, tier: string, source: string): AgentDefinition {
  const text = source.replace(/^\uFEFF/, "");
  const match = FRONTMATTER.exec(text);
  if (!match) throw new Error(`Sniff agent ${id} has no frontmatter`);
  const description = /^description:(.*)$/m.exec(match[1] ?? "")?.[1];
  if (!description) throw new Error(`Sniff agent ${id} has no description`);
  return { id, description: unquote(description), system: text.slice(match[0].length).trim(), tier };
}

export const SNIFF_AGENTS: readonly AgentDefinition[] = [
  parseAgentSource("bloodhound", "strong", bloodhoundSource),
  parseAgentSource("refactor-challenger", "reviewer", refactorChallengerSource),
];

type PermissionRule = { readonly action: string; readonly resource: string; readonly effect: "allow" | "ask" | "deny" };

/**
 * Read-only subagent policy: deny everything, then allow reading, searching, read-only shell
 * diagnostics, the web, and this plugin's own skill files outside the project.
 */
export function sniffAgentPermissions(skillDirectory: string): PermissionRule[] {
  return [
    { action: "*", resource: "*", effect: "deny" },
    { action: "read", resource: "*", effect: "allow" },
    { action: "read", resource: "*.env", effect: "ask" },
    { action: "read", resource: "*.env.*", effect: "ask" },
    { action: "read", resource: "*.env.example", effect: "allow" },
    { action: "grep", resource: "*", effect: "allow" },
    { action: "glob", resource: "*", effect: "allow" },
    { action: "lsp_*", resource: "*", effect: "allow" },
    { action: "shell", resource: "*", effect: "allow" },
    { action: "skill", resource: "sniff", effect: "allow" },
    { action: "webfetch", resource: "*", effect: "allow" },
    { action: "websearch", resource: "*", effect: "allow" },
    { action: "external_directory", resource: "*", effect: "ask" },
    { action: "external_directory", resource: `${skillDirectory}/*`, effect: "allow" },
  ];
}

type AgentDraft = {
  name?: string;
  description?: string;
  mode?: string;
  system?: string;
  request?: { headers?: Record<string, string> } & Record<string, unknown>;
  permissions?: PermissionRule[];
};

/** Fill one agent from its definition; an agent the user already configured keeps its own fields. */
export function shapeSniffAgent(draft: AgentDraft, agent: AgentDefinition, permissions: readonly PermissionRule[], created: boolean): void {
  draft.name ??= agent.id;
  draft.description ??= agent.description;
  if (created || draft.mode === undefined) draft.mode = "subagent";
  draft.system ??= agent.system;
  draft.request = { ...draft.request, headers: { [MODEL_ROLE_HEADER]: agent.tier, ...draft.request?.headers } };
  draft.permissions = [...(draft.permissions ?? []), ...permissions];
}

/** The `Skill.Info` for the shipped `SKILL.md` at absolute `path`. */
export function sniffSkillInfo(path: string): Skill.Info {
  const text = readFileSync(path, "utf8").replace(/^\uFEFF/, "");
  const match = FRONTMATTER.exec(text);
  const frontmatter = match?.[1] ?? "";
  const name = /^name:(.*)$/m.exec(frontmatter)?.[1];
  const description = /^description:(.*)$/m.exec(frontmatter)?.[1];
  if (!name) throw new Error(`Sniff skill ${path} has no name`);
  return {
    id: unquote(name),
    name: unquote(name),
    ...(description ? { description: unquote(description) } : {}),
    path,
    content: match ? text.slice(match[0].length) : text,
  } as unknown as Skill.Info;
}

function bounded(text: string): string {
  return utf8Prefix(text, MAX_MODEL_CONTENT_BYTES);
}

function planResource(plan: CanonicalConfirmationRequest): string {
  return `${plan.target.kind}:${plan.target.repository ?? plan.target.root}`;
}

type IntakeParams = { readonly input: unknown };
type CancelParams = { readonly capability: string; readonly manifestId: string };
type InstallParams = { readonly mode?: SniffInstallMode; readonly bundles?: readonly string[]; readonly all?: boolean; readonly dryRun?: boolean; readonly path?: string };
type AnalyzerParams = { readonly capability: string; readonly manifestId: string; readonly analyzer: string };
type ReportParams = { readonly capability: string; readonly manifestId: string; readonly mode?: SniffReportMode; readonly report: unknown; readonly path?: string };
type ReportArtifactParams = { readonly readCapability: string; readonly reportId: string; readonly relativePath: string; readonly offset?: number };
type AnalyzerArtifactParams = { readonly readCapability: string; readonly analyzerResultId: string; readonly relativePath?: string; readonly sourcePath?: string; readonly offset?: number; readonly maxBytes?: number };

function leaseIsLive(capability: string, manifestId: string): boolean {
  try {
    readRunManifest(capability, manifestId);
    return true;
  } catch {
    return false;
  }
}

/** The OpenCode V2 plugin: the seven Sniff tools, the Sniff skill, and its two read-only subagents. */
export function sniffOpenCodePlugin(options: SniffOpenCodeOptions): Plugin.Plugin {
  return {
    id: SNIFF_PLUGIN_ID,
    async setup(ctx: Plugin.Context) {
      const base = ctx.location.directory;
      const confirm = ctx.options.confirm !== false;
      // Leases this instance issued. The core registry is process-wide and shared with every other
      // location's instance, so unloading releases only these, never every run in the server.
      const owned = new Map<string, string>();
      // Aborted on unload so in-flight installs, analyzers, and approvals stop with the instance.
      const lifetime = new AbortController();
      let disposed = false;
      const UNLOADED = "The Sniff plugin was unloaded";

      /** The call's signal joined with the instance lifetime; throws once either has ended. */
      const begin = (context: ToolContext): AbortSignal => {
        if (disposed) throw new Error(UNLOADED);
        const signal = AbortSignal.any([context.signal, lifetime.signal]);
        signal.throwIfAborted();
        return signal;
      };

      const live = (signal: AbortSignal): void => {
        if (disposed) throw new Error(UNLOADED);
        signal.throwIfAborted();
      };

      // Checked before and after the prompt: an unload removes the escalation hook, so an approval
      // that starts or resolves after cleanup must never reach the gated action.
      const approve = async (context: ToolContext, signal: AbortSignal, action: string, resources: readonly string[], summary: string, digest?: string): Promise<void> => {
        live(signal);
        await ctx.permission.assert({
          sessionID: context.sessionID,
          agent: context.agent,
          source: { type: "tool", messageID: context.messageID, id: context.id },
          action,
          resources: [...resources],
          metadata: { summary, ...(digest ? { digest } : {}) },
        });
        live(signal);
      };

      const adopt = async (lease: RunLeaseReceipt, signal: AbortSignal): Promise<void> => {
        if (disposed || signal.aborted) {
          await cancelRunLease(lease.capability, lease.manifestId).catch(() => undefined);
          throw new Error(disposed ? `${UNLOADED}; the run was released.` : "The Sniff intake was cancelled; the run was released.");
        }
        owned.set(lease.capability, lease.manifestId);
      };

      const intake = async (input: unknown, context: ToolContext): Promise<ToolResult> => {
        const signal = begin(context);
        const parsed = intakeInput((input as IntakeParams).input);
        const request: IntakeInput = parsed.target ? { ...parsed, target: anchorTarget(parsed.target, base) } : parsed;
        const confirmPlan = async (plan: CanonicalConfirmationRequest): Promise<IntakeAuthorization> => {
          await approve(context, signal, CONFIRM_ACTIONS.intake, [planResource(plan)], intakeConfirmationText(plan, { maxFiles: MAX_PROMPT_FILES }), plan.digest);
          return { acceptedDigest: plan.digest, actor: APPROVAL_ACTOR, reason: APPROVAL_REASON };
        };
        // `interactive: false` only skips the adaptive interview; its plan still needs the same
        // host approval, so a model argument can never stand in for the user.
        const result = await runSniffIntakeTool({ input: request }, { confirmInteractive: confirmPlan, authority: { authorize: confirmPlan } });
        if (result.lease) await adopt(result.lease, signal);
        const publicResult = publicSniffIntakeResult(result);
        return { content: JSON.stringify(publicResult), metadata: { ok: true, leased: publicResult.lease !== undefined } };
      };

      const cancel = async (input: unknown): Promise<ToolResult> => {
        const { capability, manifestId } = input as CancelParams;
        await cancelRunLease(capability, manifestId);
        owned.delete(capability);
        return { content: "Sniff run cancelled and materialization released.", metadata: { ok: true } };
      };

      const install = async (input: unknown, context: ToolContext): Promise<ToolResult> => {
        const signal = begin(context);
        const params = input as InstallParams;
        const mode = params.mode ?? "probe";
        if (!INSTALL_MODES.has(mode)) throw new Error("sniff_install_tools mode must be probe, diagnose, list, or install");
        const common = {
          ...(params.bundles ? { bundles: [...params.bundles] } : {}),
          ...(params.all !== undefined ? { all: params.all } : {}),
          ...(params.dryRun !== undefined ? { dryRun: params.dryRun } : {}),
          signal,
        };
        let result: SniffInstallResult;
        if (mode === "install") {
          if (params.path !== undefined) throw new Error("sniff_install_tools mode=install does not accept path; installs run from the session directory and a Sniff-owned toolkit");
          // The core's digest-bound plan, confirmed exactly as the OMP and MCP adapters do, dry runs included.
          const options = { ...common, cwd: base };
          const request = await sniffInstallAuthorizationRequest(options);
          await approve(context, signal, CONFIRM_ACTIONS.install, request.bundles.length > 0 ? [...request.bundles] : ["*"], installConfirmationText(request), request.digest);
          live(signal);
          result = await runSniffInstall({ ...options, mode: "install" });
        } else {
          result = await runSniffInstall({ ...common, mode, cwd: params.path === undefined ? base : anchorPath(params.path, base) });
        }
        if (!result.ok) throw new Error(bounded(result.report));
        return { content: bounded(result.report), metadata: { ok: true, tools: result.tools.length } };
      };

      const analyzer = async (input: unknown, context: ToolContext): Promise<ToolResult> => {
        const signal = begin(context);
        const { capability, manifestId, analyzer: recipe } = input as AnalyzerParams;
        const result = await runSniffAnalyzer({ capability, manifestId, analyzer: recipe, signal });
        if (!result.ok) throw new Error(bounded(result.report));
        return {
          content: JSON.stringify(analyzerProjection(recipe, result)),
          metadata: { ok: true, outcome: result.outcome, preflight: publicPreflight(result.preflight), ...(result.observationPreview ? { observationPreview: result.observationPreview } : {}) },
        };
      };

      const report = async (input: unknown, context: ToolContext): Promise<ToolResult> => {
        const signal = begin(context);
        const params = input as ReportParams;
        try {
          const result = await runSniffReportTool({
            capability: params.capability,
            manifestId: params.manifestId,
            ...(params.mode ? { mode: params.mode } : {}),
            report: params.report as ReportInput,
            ...(params.path !== undefined ? { path: anchorPath(params.path, base) } : {}),
            runtime: {
              authorizeSave: async (request) => {
                await approve(context, signal, CONFIRM_ACTIONS.save, [request.directory], saveConfirmationText(request), request.digest);
                return { acceptedDigest: request.digest, actor: APPROVAL_ACTOR, reason: APPROVAL_REASON };
              },
            },
          });
          const savedPaths = result.publicArtifacts.descriptors.flatMap((descriptor) => (descriptor.savedPath ? [descriptor.savedPath] : []));
          return { content: reportRenderContent(result.publicArtifacts), metadata: { ok: true, reportId: result.publicArtifacts.reportId, savedPaths } };
        } finally {
          // A malformed report keeps its lease for a corrected retry; every other outcome ends it.
          // Liveness uses the recorded manifest ID: a call with a wrong ID must not drop ownership.
          const manifestId = owned.get(params.capability);
          if (manifestId !== undefined && !leaseIsLive(params.capability, manifestId)) owned.delete(params.capability);
        }
      };

      const reportArtifact = async (input: unknown, context: ToolContext): Promise<ToolResult> => {
        begin(context);
        const { readCapability, ...options } = input as ReportArtifactParams;
        const { text, page } = reportArtifactPage(readReportArtifact({ ...options, capability: readCapability }));
        return { content: text, metadata: { ok: true, nextOffset: page.nextOffset, eof: page.eof } };
      };

      const analyzerArtifact = async (input: unknown, context: ToolContext): Promise<ToolResult> => {
        begin(context);
        const { readCapability, maxBytes, ...options } = input as AnalyzerArtifactParams;
        if ((options.relativePath === undefined) === (options.sourcePath === undefined)) throw new Error("Provide exactly one of relativePath or sourcePath");
        const { text, page } = analyzerArtifactPage(readAnalyzerArtifact({ ...options, capability: readCapability }), analyzerPageLimit(maxBytes));
        return { content: text, metadata: { ok: true, nextOffset: page.nextOffset, eof: page.eof } };
      };

      const registrations: Registration[] = [];
      const cleanup = async (): Promise<void> => {
        disposed = true;
        lifetime.abort(new Error(UNLOADED));
        const leases = [...owned];
        owned.clear();
        await Promise.allSettled(leases.map(([capability, manifestId]) => cancelRunLease(capability, manifestId)));
        for (const registration of registrations.splice(0).reverse()) await registration.dispose();
      };

      try {
        registrations.push(await ctx.tool.transform((editor) => {
          editor.add({
            name: "sniff_intake",
            description: "Resolve the Sniff intake plan; once the user approves it, issue a run capability and manifest ID.\nRepeat with resolved axes until a plan is ready. The approval is a permission prompt; copy reportTarget into sniff_report.",
            input: sniffToolInputSchemas.sniff_intake,
            execute: intake,
          });
          editor.add({
            name: "sniff_cancel",
            description: "Cancel a Sniff run and release its temporary materialization.",
            input: sniffToolInputSchemas.sniff_cancel,
            execute: cancel,
          });
          editor.add({
            name: "sniff_install_tools",
            description: "Probe, diagnose, or list Sniff analyzers read-only, or install bundles after a permission prompt.\nDefault mode is probe. Installs use a Sniff-owned toolkit through mise and never sudo.",
            input: sniffToolInputSchemas.sniff_install_tools,
            execute: install,
          });
          editor.add({
            name: "sniff_run_analyzer",
            description: "Run one analyzer recipe selected by a live Sniff manifest.\nPass only the capability, manifest ID, and recipe ID; page complete observations with sniff_read_analyzer_artifact.",
            input: sniffToolInputSchemas.sniff_run_analyzer,
            execute: analyzer,
          });
          editor.add({
            name: "sniff_report",
            description: "Validate and render a Sniff report, or save it after a permission prompt.\nCopy reportTarget from sniff_intake into report.target, add languages, and omit extensions[\"sniff.intake\"].",
            input: sniffToolInputSchemas.sniff_report,
            execute: report,
          });
          editor.add({
            name: "sniff_read_report_artifact",
            description: "Read one UTF-8-safe page (at most 64 KiB) of a Sniff report artifact; continue with nextOffset until eof.",
            input: sniffToolInputSchemas.sniff_read_report_artifact,
            execute: reportArtifact,
          });
          editor.add({
            name: "sniff_read_analyzer_artifact",
            description: "Read one UTF-8-safe page of complete analyzer observations; give relativePath or sourcePath.\nContinue with nextOffset until eof.",
            input: sniffToolInputSchemas.sniff_read_analyzer_artifact,
            execute: analyzerArtifact,
          });
        }));
        registrations.push(await ctx.permission.hook("evaluate", (evaluation) => confirmSniffApproval(evaluation, confirm)));
        const skill = sniffSkillInfo(options.skillPath);
        registrations.push(await ctx.skill.transform((editor) => {
          if (editor.get(skill.id) === undefined) editor.add(skill);
        }));
        const permissions = sniffAgentPermissions(dirname(options.skillPath));
        registrations.push(await ctx.agent.transform((editor) => {
          for (const agent of SNIFF_AGENTS) {
            const created = editor.get(agent.id) === undefined;
            editor.update(agent.id, (draft) => shapeSniffAgent(draft as unknown as AgentDraft, agent, permissions, created));
          }
        }));
      } catch (error) {
        await cleanup();
        throw error;
      }
      return cleanup;
    },
  };
}
