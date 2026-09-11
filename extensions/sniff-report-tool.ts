import type { TSchema } from "@oh-my-pi/pi-ai";
import type { ExtensionAPI, ExtensionContext } from "@oh-my-pi/pi-coding-agent";
import {
	runSniffReportTool,
	type SaveAuthorizationRequest,
	type SniffReportRuntime,
	type SniffReportToolOptions,
} from "../src/core/report-use-case.ts";

function saveConfirmationMessage(request: SaveAuthorizationRequest): string {
	return [
		`Canonical directory: ${request.directory}`,
		`Manifest ID: ${request.manifestId}`,
		`Report ID: ${request.reportId}`,
		`Artifact filenames: ${request.files.join(", ")}`,
		`Save digest: ${request.digest}`,
	].join("\n");
}

function runtimeForContext(ctx: ExtensionContext): SniffReportRuntime {
	return {
		authorizeSave: async (request) => {
			if (!ctx.hasUI) return false;
			const approved = await ctx.ui.confirm("Confirm Sniff report save", saveConfirmationMessage(request));
			return approved ? { acceptedDigest: request.digest, actor: "interactive-user", reason: "Confirmed through the OMP UI boundary." } : false;
		},
	};
}

export default function sniffReportTool(pi: ExtensionAPI): void {
	const z = pi.zod;
	pi.registerTool<TSchema, { readonly ok: boolean; readonly error?: string }>({
		name: "sniff_report",
		label: "Sniff structured report",
		description: "Build a canonical Sniff report only for a live sniff_intake capability, validate the serialized issued manifest, and release its materialization after terminal success or failure.",
		parameters: z.object({
			capability: z.string().describe("Opaque capability returned by sniff_intake"),
			manifestId: z.string().describe("Opaque manifest ID returned by sniff_intake"),
			mode: z.enum(["render", "save"]).optional().describe("render (default) or explicit save"),
			report: z.unknown().describe("Report input including the exact issued sniff.intake manifest extension"),
			path: z.string().optional().describe("Output directory required only for save mode"),
		}) as unknown as TSchema,
		execute: async (_id, params: SniffReportToolOptions, _signal, _onUpdate, ctx) => {
			try {
				const result = await runSniffReportTool({ ...params, runtime: runtimeForContext(ctx) });
				return {
					content: [{ type: "text", text: result.artifacts.markdown }],
					details: { ok: true, report: result.artifacts.report, receipt: result.artifacts.receipt, savedPaths: result.savedPaths },
				};
			} catch (error) {
				const message = error instanceof Error ? error.message : String(error);
				return { content: [{ type: "text", text: `sniff_report failed: ${message}` }], details: { ok: false, error: message, savedPaths: [] }, isError: true };
			}
		},
	});
}
