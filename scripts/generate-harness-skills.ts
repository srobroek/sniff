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

const SOURCE_DIRECTORY = join("skills", "sniff");
const TARGET_DIRECTORIES = [
	join(".claude", "skills", "sniff"),
	join(".agents", "skills", "sniff"),
];
const MARKDOWN_EXTENSIONS: Record<string, true> = { ".md": true, ".mdx": true };

function rewriteSkillText(contents: string): string {
	return contents
		.replaceAll(/skill:\/\/sniff\//g, "./")
		.replaceAll(/skill:\/\/sniff/g, ".")
		.replaceAll(/bloodhound/gi, "independent scout")
		.replaceAll(/refactor-challenger/gi, "independent challenge reviewer")
		.replaceAll(/a `independent scout`/g, "an independent scout")
		.replaceAll(
			/a `independent challenge reviewer`/g,
			"an independent challenge reviewer",
		)
		.replaceAll(
			"For large targets, propose an independent scout plan by language and subtree.",
			"For large targets, propose an independent read-only scout plan by language and subtree.",
		)
		.replaceAll(
			"Build the `independent challenge reviewer` brief from `./references/adversarial-brief.md`.",
			"Run an independent read-only challenge pass using `./references/adversarial-brief.md`.",
		)
		.replaceAll(
			"- MUST resolve shipped assets through `./`.",
			"- MUST resolve shipped assets through this skill's `references/` directory.",
		)
		.replaceAll(
			"- MUST prefix Sniff Bash commands with `OMP_SNIFF_ACTIVE=1`.",
			"- MUST run Sniff Bash commands only after the issued capability and one-shot recipe authorization are verified.",
		);
}

function collectFiles(
	sourceRoot: string,
	currentDirectory = sourceRoot,
): GeneratedFile[] {
	const entries = readdirSync(currentDirectory, { withFileTypes: true }).sort(
		(left, right) => left.name.localeCompare(right.name),
	);
	const files: GeneratedFile[] = [];

	for (const entry of entries) {
		const absolutePath = join(currentDirectory, entry.name);
		if (entry.isDirectory()) {
			files.push(...collectFiles(sourceRoot, absolutePath));
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
			MARKDOWN_EXTENSIONS[extension] === true
				? Buffer.from(rewriteSkillText(sourceBytes.toString("utf8")), "utf8")
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

	const files = collectFiles(sourceRoot);
	const targets = TARGET_DIRECTORIES.map((directory) =>
		join(repoRoot, directory),
	);
	const current = targets.every((target) => targetIsCurrent(target, files));
	if (options.check) {
		if (!current) {
			throw new Error(
				"Generated harness skill output is stale; run the generator without --check.",
			);
		}
		return { files: files.length, targets, changed: false };
	}

	for (const target of targets) {
		writeTarget(target, files);
	}
	return { files: files.length, targets, changed: !current };
}

function runFromCli(): void {
	const args = process.argv.slice(2);
	if (args.some((argument) => argument !== "--check")) {
		throw new Error("Usage: bun scripts/generate-harness-skills.ts [--check]");
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
