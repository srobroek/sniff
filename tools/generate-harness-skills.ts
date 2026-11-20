import {
	existsSync,
	mkdirSync,
	readdirSync,
	readFileSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import { dirname, join, relative, resolve } from "node:path";

type GeneratedFile = {
	relativePath: string;
	contents: Uint8Array;
};

type GenerateOptions = {
	repoRoot?: string;
	check?: boolean;
};

type GenerateResult = {
	files: number;
	targets: string[];
	changed: boolean;
};

type Rewrite = "none" | "portable" | "opencode";

type Target = {
	directory: string;
	rewrite: Rewrite;
};

const SOURCE_DIRECTORY = join(".skill-source", "sniff");
const TARGETS: Target[] = [
	{ directory: join("skills", "sniff"), rewrite: "none" },
	{ directory: join(".claude", "skills", "sniff"), rewrite: "portable" },
	{ directory: join(".agents", "skills", "sniff"), rewrite: "portable" },
	{ directory: join("dist", "codex", "skills", "sniff"), rewrite: "portable" },
	{ directory: join("dist", "opencode", "skills", "sniff"), rewrite: "opencode" },
];
const MARKDOWN_EXTENSIONS: Record<string, true> = { ".md": true, ".mdx": true };

function rewriteSkillUris(contents: string): string {
	return contents
		.replaceAll(/skill:\/\/sniff\//g, "./")
		.replaceAll(/skill:\/\/sniff/g, ".")
		.replaceAll(
			"- MUST resolve shipped assets through `./`.",
			"- MUST resolve shipped assets through this skill's `references/` directory.",
		);
}

const CHALLENGE_CHAIN =
	"Send the brief to the first of these that exists: the `refactor-challenger` agent (it ships with the code-challenge plugin), the `adversarial-challenger` agent, or a fresh-context read-only subagent that receives the brief verbatim. For the subagent, record reduced independence in report coverage. Never skip the challenge silently.";
const BRIEF_INTRO =
	"Use this to build the step-6 prompt for the challenger. Step 6 of the skill picks the agent.";

function rewritePortableSkillText(contents: string): string {
	const rewritten = rewritePortableSkillTextUnchecked(contents);
	// A phrase that drifts from its source would leave agent names in tools that lack them.
	if (/refactor-challenger|adversarial-challenger/.test(rewritten)) {
		throw new Error(
			"Portable skill text still names a challenger agent; update the rewrite phrases in tools/generate-harness-skills.ts.",
		);
	}
	return rewritten;
}

function rewritePortableSkillTextUnchecked(contents: string): string {
	return rewriteSkillUris(contents)
		.replaceAll(/bloodhound/gi, "independent scout")
		.replaceAll(/a `independent scout`/g, "an independent scout")
		.replaceAll(
			"For large targets, propose an independent scout plan by language and subtree.",
			"For large targets, propose an independent read-only scout plan by language and subtree.",
		)
		.replaceAll(
			`Build the challenge brief from \`./references/adversarial-brief.md\`. ${CHALLENGE_CHAIN}`,
			"Run an independent read-only challenge pass using `./references/adversarial-brief.md`. Never skip it silently.",
		)
		.replaceAll(
			BRIEF_INTRO,
			"Use this to build the step-6 prompt for an independent read-only challenge reviewer.",
		);
}

// OpenCode registers `bloodhound` as a subagent, so the name stays. The challenger comes from the code-challenge plugin or the host.
// A subagent starts in a fresh context, so it gets absolute paths rather than skill-relative ones.
function rewriteOpenCodeSkillText(contents: string): string {
	return rewriteSkillUris(contents)
		.replaceAll(
			"and include the matching `./references/languages/<lang>.md` path.",
			"and include the absolute path of the matching `references/languages/<lang>.md` under this skill's base directory. Launch each `bloodhound` with the `subagent` tool.",
		)
		.replaceAll(
			`${CHALLENGE_CHAIN} Drop or downgrade refuted findings.`,
			`${CHALLENGE_CHAIN} Launch it with the \`subagent\` tool. Drop or downgrade refuted findings.`,
		)
		.replaceAll(
			"   - Ask only the highest-impact unresolved question.",
			"   - Ask only the highest-impact unresolved question, with the `question` tool.",
		)
		.replaceAll(
			"   - Probing is safe. Installing needs host confirmation.",
			"   - Probing is safe. Installing needs host confirmation, which OpenCode shows as a permission prompt.",
		);
}

const REWRITES: Record<Rewrite, (contents: string) => string> = {
	none: (contents) => contents,
	portable: rewritePortableSkillText,
	opencode: rewriteOpenCodeSkillText,
};

function collectFiles(
	sourceRoot: string,
	rewrite: Rewrite,
	currentDirectory = sourceRoot,
): GeneratedFile[] {
	const entries = readdirSync(currentDirectory, { withFileTypes: true }).sort(
		(left, right) => left.name.localeCompare(right.name),
	);
	const files: GeneratedFile[] = [];

	for (const entry of entries) {
		const absolutePath = join(currentDirectory, entry.name);
		if (entry.isDirectory()) {
			files.push(
				...collectFiles(sourceRoot, rewrite, absolutePath),
			);
			continue;
		}
		if (!entry.isFile()) {
			throw new Error(`Unsupported authored skill entry: ${absolutePath}`);
		}

		const relativePath = relative(sourceRoot, absolutePath)
			.split("\\")
			.join("/");
		const sourceBytes = readFileSync(absolutePath);
		const extension = absolutePath.slice(absolutePath.lastIndexOf("."));
		const contents =
			rewrite !== "none" && MARKDOWN_EXTENSIONS[extension] === true
				? Buffer.from(REWRITES[rewrite](sourceBytes.toString("utf8")), "utf8")
				: sourceBytes;
		files.push({ relativePath, contents });
	}

	return files.sort((left, right) =>
		left.relativePath.localeCompare(right.relativePath),
	);
}

function fileContentsMatch(path: string, expected: Uint8Array): boolean {
	if (!existsSync(path)) {
		return false;
	}
	const actual = readFileSync(path);
	return (
		actual.byteLength === expected.byteLength &&
		actual.every((byte, index) => byte === expected[index])
	);
}

function directoryEntries(directory: string): string[] {
	if (!existsSync(directory)) {
		return [];
	}
	const entries: string[] = [];
	const visit = (currentDirectory: string): void => {
		for (const entry of readdirSync(currentDirectory, {
			withFileTypes: true,
		})) {
			const absolutePath = join(currentDirectory, entry.name);
			if (entry.isDirectory()) {
				visit(absolutePath);
			} else if (entry.isFile()) {
				entries.push(relative(directory, absolutePath).split("\\").join("/"));
			} else {
				entries.push(relative(directory, absolutePath).split("\\").join("/"));
			}
		}
	};
	visit(directory);
	return entries.sort((left, right) => left.localeCompare(right));
}

function targetIsCurrent(
	targetDirectory: string,
	files: GeneratedFile[],
): boolean {
	const expectedPaths = files.map((file) => file.relativePath);
	const actualPaths = directoryEntries(targetDirectory);
	if (
		expectedPaths.length !== actualPaths.length ||
		expectedPaths.some((path, index) => path !== actualPaths[index])
	) {
		return false;
	}
	return files.every((file) =>
		fileContentsMatch(join(targetDirectory, file.relativePath), file.contents),
	);
}

function writeTarget(targetDirectory: string, files: GeneratedFile[]): void {
	rmSync(targetDirectory, { recursive: true, force: true });
	mkdirSync(targetDirectory, { recursive: true });
	for (const file of files) {
		const path = join(targetDirectory, file.relativePath);
		mkdirSync(dirname(path), { recursive: true });
		writeFileSync(path, file.contents);
	}
}

export function generateHarnessSkills(
	options: GenerateOptions = {},
): GenerateResult {
	const repoRoot = resolve(options.repoRoot ?? join(import.meta.dir, ".."));
	const sourceRoot = join(repoRoot, SOURCE_DIRECTORY);
	if (!existsSync(sourceRoot)) {
		throw new Error(`Authored skill directory does not exist: ${sourceRoot}`);
	}

	const targets = TARGETS.map((target) => ({
		directory: join(repoRoot, target.directory),
		files: collectFiles(sourceRoot, target.rewrite),
	}));
	const current = targets.every((target) =>
		targetIsCurrent(target.directory, target.files),
	);
	if (options.check) {
		if (!current) {
			throw new Error(
				"Generated harness skill output is stale; run the generator without --check.",
			);
		}
		return {
			files: targets[0]?.files.length ?? 0,
			targets: targets.map((target) => target.directory),
			changed: false,
		};
	}

	for (const target of targets) {
		writeTarget(target.directory, target.files);
	}
	return {
		files: targets[0]?.files.length ?? 0,
		targets: targets.map((target) => target.directory),
		changed: !current,
	};
}

function runFromCli(): void {
	const args = process.argv.slice(2);
	if (args.some((argument) => argument !== "--check")) {
		throw new Error("Usage: bun tools/generate-harness-skills.ts [--check]");
	}
	const result = generateHarnessSkills({ check: args.includes("--check") });
	const action = args.includes("--check")
		? "current"
		: result.changed
			? "generated"
			: "unchanged";
	console.log(
		`${action} ${result.files} harness skill files in ${result.targets.length} trees`,
	);
}

if (import.meta.main) {
	try {
		runFromCli();
	} catch (error) {
		console.error(error instanceof Error ? error.message : error);
		process.exitCode = 1;
	}
}
