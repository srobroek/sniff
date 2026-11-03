import { fileURLToPath } from "node:url";
import { sniffOpenCodePlugin } from "./plugin.ts";

// Bundled to dist/opencode/index.js, beside the generated skills/sniff tree.
export default sniffOpenCodePlugin({ skillPath: fileURLToPath(new URL("./skills/sniff/SKILL.md", import.meta.url)) });
