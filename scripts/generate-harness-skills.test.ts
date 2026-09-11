import { expect, test } from "bun:test";
import {
	cpSync,
	mkdtempSync,
	readFileSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { generateHarnessSkills } from "./generate-harness-skills.ts";

const repoRoot = resolve(import.meta.dir, "..");
const generatedRoots = [
	join(repoRoot, ".claude", "skills", "sniff"),
	join(repoRoot, ".agents", "skills", "sniff"),
];

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

test("apply followed by check is deterministic", () => {
	const result = generateHarnessSkills({ repoRoot });
	expect(result.files).toBeGreaterThan(1);
	expect(generateHarnessSkills({ repoRoot, check: true }).changed).toBe(false);
});

test("generated skills preserve the five-tool workflow and security gates", () => {
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
	expect(skill).toContain(
		"Pass the capability and manifest ID to `sniff_report`.",
	);
});

test("generated markdown contains no OMP-only URI, directive, or agent name", () => {
	const markdown = generatedMarkdown();
	expect(markdown).not.toMatch(/skill:\/\//);
	expect(markdown).not.toContain("OMP_SNIFF_ACTIVE=1");
	expect(markdown).not.toMatch(/\b(?:bloodhound|refactor-challenger|TTSR)\b/i);
	expect(markdown).toContain("independent read-only challenge pass");
});

test("check mode rejects stale generated output", () => {
	const fixture = mkdtempSync(join(tmpdir(), "sniff-generator-"));
	try {
		cpSync(
			join(repoRoot, "skills", "sniff"),
			join(fixture, "skills", "sniff"),
			{ recursive: true },
		);
		generateHarnessSkills({ repoRoot: fixture });
		const generatedSkill = join(
			fixture,
			".claude",
			"skills",
			"sniff",
			"SKILL.md",
		);
		writeFileSync(
			generatedSkill,
			`${readFileSync(generatedSkill, "utf8")}\n stale\n`,
		);
		expect(() =>
			generateHarnessSkills({ repoRoot: fixture, check: true }),
		).toThrow("stale");
	} finally {
		rmSync(fixture, { recursive: true, force: true });
	}
});
