import type { ExtensionAPI } from "@oh-my-pi/pi-coding-agent";
import sniffInstallTool from "./sniff-install-tool.ts";
import sniffIntakeTool from "./sniff-intake-tool.ts";
import sniffReportTool from "./sniff-report-tool.ts";

export default function sniffPlugin(pi: ExtensionAPI): void {
	sniffInstallTool(pi);
	sniffIntakeTool(pi);
	sniffReportTool(pi);
}
