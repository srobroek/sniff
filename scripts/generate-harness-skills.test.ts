import { expect, test } from "bun:test";
import {
	cpSync,
	mkdtempSync,
	readdirSync,
	readFileSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, relative, resolve } from "node:path";
import { generateHarnessSkills } from "./generate-harness-skills.ts";

const repoRoot = resolve(import.meta.dir, "..");
const authoredRoot = join(repoRoot, ".skill-source", "sniff");
const ompRoot = join(repoRoot, "skills", "sniff");
const generatedRoots = [
	join(repoRoot, ".claude", "skills", "sniff"),
	join(repoRoot, ".agents", "skills", "sniff"),
	join(repoRoot, "dist", "codex", "skills", "sniff"),
] as const;

function filesUnder(root: string): string[] {
	const files: string[] = [];
	const visit = (directory: string): void => {
		for (const entry of readdirSync(directory, { withFileTypes: true })) {
			const path = join(directory, entry.name);
			if (entry.isDirectory()) {
				visit(path);
			} else if (entry.isFile()) {
				files.push(relative(root, path));
			}
		}
	};
	visit(root);
	return files.sort();
}

function generatedMarkdown(): string {
	return generatedRoots
		.flatMap((root) => [
			join(root, "SKILL.md"),
			join(root, "references", "approval-gates.md"),
			join(root, "references", "intake.md"),
		])
		.map((path) => readFileSync(path, "utf8"))
		.join("\n");
}

function createFixture(): string {
	const fixture = mkdtempSync(join(tmpdir(), "sniff-generator-"));
	cpSync(authoredRoot, join(fixture, ".skill-source", "sniff"), {
		recursive: true,
	});
	return fixture;
}

function removeFixture(fixture: string): void {
	rmSync(fixture, { recursive: true, force: true });
}

test("repository outputs pass check mode without writing", () => {
	const result = generateHarnessSkills({ repoRoot, check: true });
	expect(result.changed).toBe(false);
	expect(result.targets).toHaveLength(4);
});

test("write mode writes only temporary output trees", () => {
	const fixture = createFixture();
	try {
		const result = generateHarnessSkills({ repoRoot: fixture });
		expect(result.files).toBeGreaterThan(1);
		expect(result.targets).toHaveLength(4);
		expect(generateHarnessSkills({ repoRoot: fixture, check: true }).changed).toBe(
			false,
		);
		expect(filesUnder(join(fixture, "skills", "sniff"))).toEqual(
		filesUnder(join(fixture, "dist", "codex", "skills", "sniff")),
		);
	} finally {
		removeFixture(fixture);
	}
});

test("generated skills preserve the seven-tool workflow and security gates", () => {
	const skill = readFileSync(join(generatedRoots[0], "SKILL.md"), "utf8");
	const sequence = [
		"sniff_intake",
		"sniff_install_tools",
		"sniff_run_analyzer",
		"sniff_report",
		"sniff_cancel",
	];
	let previousIndex = -1;
	for (const tool of sequence) {
		const index = skill.indexOf(tool);
		expect(index).toBeGreaterThan(previousIndex);
		previousIndex = index;
	}

	const intake = readFileSync(
		join(generatedRoots[0], "references", "intake.md"),
		"utf8",
	);
	for (const axis of ["target", "intent", "objectives", "budget"]) {
		expect(intake).toContain(`- ${axis}`);
	}
	expect(intake).toContain(
		"Keep installation and report saving as separate approvals.",
	);
	expect(intake).toContain(
		"Call `sniff_cancel` if the run ends without a report.",
	);
	expect(skill).toContain("Copy `reportTarget` from `sniff_intake` into `report.target`");
	expect(skill).toContain("Pass the capability and manifest ID to `sniff_report`");
});

test("generated Codex trees are OMP-free and byte-identical", () => {
	const markdown = generatedMarkdown();
	expect(markdown).not.toMatch(/skill:\/\//);
	expect(markdown).not.toContain("OMP_SNIFF_ACTIVE=1");
	expect(markdown).not.toMatch(/\b(?:bloodhound|refactor-challenger|TTSR)\b/i);

	const paths = filesUnder(generatedRoots[1]);
	expect(paths).toEqual(filesUnder(generatedRoots[2]));
	for (const path of paths) {
		expect(
			readFileSync(join(generatedRoots[1], path)),
		).toEqual(readFileSync(join(generatedRoots[2], path)));
	}
});

test("generated OMP output preserves its native skill references", () => {
	const skill = readFileSync(join(ompRoot, "SKILL.md"), "utf8");
	expect(skill).toContain("skill://sniff/references/approval-gates.md");
	expect(skill).toContain("OMP_SNIFF_ACTIVE=1");
});

test("check mode rejects stale temporary output without rewriting it", () => {
	const fixture = createFixture();
	try {
		generateHarnessSkills({ repoRoot: fixture });
		const generatedSkill = join(
			fixture,
			"dist",
			"codex",
			"skills",
			"sniff",
			"SKILL.md",
		);
		writeFileSync(
			generatedSkill,
			`${readFileSync(generatedSkill, "utf8")}\n stale\n`,
		);
		const staleContents = readFileSync(generatedSkill, "utf8");
		expect(() =>
			generateHarnessSkills({ repoRoot: fixture, check: true }),
		).toThrow("stale");
		expect(readFileSync(generatedSkill, "utf8")).toBe(staleContents);
	} finally {
		removeFixture(fixture);
	}
});
