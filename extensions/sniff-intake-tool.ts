import type { TSchema } from "@oh-my-pi/pi-ai";
import type { ExtensionAPI, ExtensionContext } from "@oh-my-pi/pi-coding-agent";
import type { SniffIntakeRuntime } from "../src/core/intake-use-case.ts";
import {
  intakeInput,
  runSniffIntakeTool,
  type SniffIntakeToolResult,
} from "../src/core/intake-use-case.ts";
import { cancelRunLease } from "../src/core/run-registry.ts";

function runtimeForContext(ctx: ExtensionContext, hostAuthorized: boolean): SniffIntakeRuntime {
  return {
    confirmInteractive: async ({ target, files }) => {
      if (!ctx.hasUI) return false;
      return ctx.ui.confirm("Confirm Sniff intake", `Inspect ${files} files from ${target}?`);
    },
    authority: {
      authorize: async ({ target, intent }) => {
        if (!ctx.hasUI) {
          return hostAuthorized
            ? { actor: "extension-host", reason: "The host executed the read-approved sniff_intake tool." }
            : false;
        }
        const granted = await ctx.ui.confirm("Authorize noninteractive Sniff intake", `Authorize ${intent} for ${target.label}?`);
        return granted ? { actor: "interactive-user", reason: "Confirmed through the OMP UI boundary." } : false;
      },
    },
  };
}

export default function sniffIntakeTool(pi: ExtensionAPI): void {
  const z = pi.zod;
  pi.registerTool<TSchema, { readonly ok: boolean; readonly result?: SniffIntakeToolResult; readonly error?: string }>({
    name: "sniff_intake",
    label: "Sniff adaptive intake",
    description: "Resolve the Sniff decision frontier and materialize an immutable target before issuing a validated run manifest.",
    approval: "read",
    parameters: z.object({ input: z.unknown().describe("Adaptive intake request") }) as unknown as TSchema,
    execute: async (_id, params: { input: unknown }, _signal, _onUpdate, ctx) => {
      try {
        const result = await runSniffIntakeTool({ input: intakeInput(params.input) }, runtimeForContext(ctx, true));
        return { content: [{ type: "text", text: JSON.stringify(result) }], details: { ok: true, result } };
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
