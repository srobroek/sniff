import type { ExtensionAPI } from "@oh-my-pi/pi-coding-agent";
import { createSniffRunOwner } from "../src/core/run-owner.ts";
import sniffInstallTool from "./sniff-install-tool.ts";
import sniffIntakeTool from "./sniff-intake-tool.ts";
import sniffReportTool from "./sniff-report-tool.ts";

export default function sniffPlugin(pi: ExtensionAPI): void {
	// One owner per extension load: its runs and artifacts are invisible to any other load in the
	// process and are released when the session shuts down.
	const owner = createSniffRunOwner({ label: "omp-extension" });
	sniffInstallTool(pi, owner);
	sniffIntakeTool(pi, owner);
	sniffReportTool(pi, owner);
	if (typeof pi.on === "function") pi.on("session_shutdown", () => owner.dispose("session shutdown"));
}
