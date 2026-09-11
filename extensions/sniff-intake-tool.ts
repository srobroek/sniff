import type { TSchema } from "@oh-my-pi/pi-ai";
import type { ExtensionAPI, ExtensionContext } from "@oh-my-pi/pi-coding-agent";
import type { CanonicalConfirmationRequest } from "../src/core/intake.ts";
import type { SniffIntakeRuntime } from "../src/core/intake-use-case.ts";
import {
	intakeInput,
	publicSniffIntakeResult,
	runSniffIntakeTool,
	type SniffIntakePublicResult,
} from "../src/core/intake-use-case.ts";
import { cancelRunLease } from "../src/core/run-registry.ts";

function confirmationMessage(request: CanonicalConfirmationRequest): string {
	const target = request.target;
	const immutableTarget = [
		`kind=${target.kind}`,
		`label=${target.label}`,
		`root=${target.root}`,
		...(target.repository ? [`repository=${target.repository}`] : []),
		...(target.immutableRef ? [`immutableRef=${target.immutableRef}`] : []),
		...(target.baseRef ? [`baseRef=${target.baseRef}`] : []),
		...(target.headRef ? [`headRef=${target.headRef}`] : []),
	].join(", ");
	const files = request.files.map((file) => `  - ${file}`).join("\n");
	const analyzers = request.analyzers.map((analyzer) => JSON.stringify(analyzer)).join("; ");
	return [
		`Immutable target/ref: ${immutableTarget}`,
		`Files (${request.files.length}):`,
		files || "  - <none>",
		`Intent: ${request.intent}`,
		`Scope mode: ${request.scopeMode}`,
		`Objectives: ${JSON.stringify(request.objectives)}`,
		`Exclusions: ${JSON.stringify(request.exclusions)}`,
		`Analyzers/dispositions: ${analyzers || "<none>"}`,
		`Budgets: ${JSON.stringify(request.budget)}`,
		`Trust: ${request.trust}`,
		`Materialization: ${request.materialization}`,
		`Plan digest: ${request.digest}`,
	].join("\n");
}

function runtimeForContext(ctx: ExtensionContext, hostAuthorized: boolean): SniffIntakeRuntime {
	return {
		confirmInteractive: async (request) => {
			if (!ctx.hasUI) return false;
			const approved = await ctx.ui.confirm("Confirm Sniff intake", confirmationMessage(request));
			return approved ? { acceptedDigest: request.digest, actor: "interactive-user" } : false;
		},
		authority: {
			authorize: async (request) => {
				if (!ctx.hasUI) return hostAuthorized ? { acceptedDigest: request.digest, actor: "extension-host", reason: "The host executed the read-approved sniff_intake tool." } : false;
				const granted = await ctx.ui.confirm("Authorize noninteractive Sniff intake", confirmationMessage(request));
				return granted ? { acceptedDigest: request.digest, actor: "interactive-user", reason: "Confirmed through the OMP UI boundary." } : false;
			},
		},
	};
}

export default function sniffIntakeTool(pi: ExtensionAPI): void {
	const z = pi.zod;
	pi.registerTool<TSchema, { readonly ok: boolean; readonly result?: SniffIntakePublicResult; readonly error?: string }>({
		name: "sniff_intake",
		label: "Sniff adaptive intake",
		description: "Resolve the Sniff decision frontier and materialize an immutable target before issuing a validated run manifest. Accepted responses include a bounded confirmation digest, a summary, and reportTarget for the matching sniff_report payload.",
		approval: "read",
		parameters: z.object({ input: z.unknown().describe("Adaptive intake request") }) as unknown as TSchema,
		execute: async (_id, params: { input: unknown }, _signal, _onUpdate, ctx) => {
			try {
				const result = await runSniffIntakeTool({ input: intakeInput(params.input) }, runtimeForContext(ctx, true));
				const publicResult = publicSniffIntakeResult(result);
				return { content: [{ type: "text", text: JSON.stringify(publicResult) }], details: { ok: true, result: publicResult } };
			} catch (error) {
				const message = error instanceof Error ? error.message : String(error);
				return { content: [{ type: "text", text: `sniff_intake failed: ${message}` }], details: { ok: false, error: message }, isError: true };
			}
		},
	});

	pi.registerTool<TSchema, { readonly ok: boolean; readonly error?: string }>({
		name: "sniff_cancel",
		label: "Cancel Sniff run",
		description: "Cancel an issued Sniff run and delete its host-owned temporary materialization exactly once.",
		approval: "read",
		parameters: z.object({
			capability: z.string().describe("Opaque capability returned by sniff_intake"),
			manifestId: z.string().describe("Manifest ID returned by sniff_intake"),
		}) as unknown as TSchema,
		execute: async (_id, params: { capability: string; manifestId: string }) => {
			try {
				cancelRunLease(params.capability, params.manifestId);
				return { content: [{ type: "text", text: "Sniff run cancelled and materialization released." }], details: { ok: true } };
			} catch (error) {
				const message = error instanceof Error ? error.message : String(error);
				return { content: [{ type: "text", text: `sniff_cancel failed: ${message}` }], details: { ok: false, error: message }, isError: true };
			}
		},
	});
}
