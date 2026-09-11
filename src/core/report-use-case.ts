import { createHash } from "node:crypto";
import { lstatSync, mkdirSync, realpathSync } from "node:fs";
import { dirname, isAbsolute, join, parse, relative, resolve, sep } from "node:path";
import type { RunManifest } from "./intake.ts";
import {
	buildSniffReport,
	createReportArtifacts,
	type ReportArtifacts,
	type ReportInput,
	type ReportTarget,
	saveReportArtifacts,
} from "./report.ts";
import { finalizeRunLease, validateReportCoverage, validateReportManifest } from "./run-registry.ts";

export type SniffReportMode = "render" | "save";
export type SaveAuthorizationRequest = {
	readonly directory: string;
	readonly manifestId: string;
	readonly reportId: string;
	readonly files: readonly string[];
	readonly digest: string;
	readonly manifest: RunManifest;
};
export type SaveAuthorizationResponse = {
	readonly acceptedDigest: string;
	readonly actor?: string;
	readonly reason?: string;
};
export type SniffReportRuntime = {
	readonly authorizeSave: (request: SaveAuthorizationRequest) => Promise<false | SaveAuthorizationResponse>;
};
export interface SniffReportToolOptions {
	capability: string;
	manifestId: string;
	mode?: SniffReportMode;
	report: ReportInput;
	path?: string;
	runtime?: SniffReportRuntime;
}
export interface SniffReportToolResult {
	artifacts: ReportArtifacts;
	savedPaths: string[];
}

const REPORT_KIND_BY_TARGET: Record<RunManifest["resolvedTarget"]["kind"], ReportTarget["kind"]> = {
	"whole-repo": "whole-repo",
	"working-tree": "uncommitted",
	files: "files",
	directory: "directory",
	module: "area",
	commit: "commit",
	range: "range",
	branch: "branch",
	ref: "ref",
	repository: "repository",
	release: "release",
	history: "history",
	pr: "pr",
	mr: "mr",
};

function authenticatedTarget(manifest: RunManifest, supplied: ReportTarget): ReportTarget {
	const resolved = manifest.resolvedTarget;
	const identity = {
		kind: REPORT_KIND_BY_TARGET[resolved.kind],
		label: resolved.label,
		baseRef: resolved.baseRef,
		filesAnalyzed: resolved.files.length,
		scopeMode: manifest.scopeMode,
	};
	if (
		supplied.kind !== identity.kind ||
		supplied.label !== identity.label ||
		supplied.baseRef !== identity.baseRef ||
		supplied.filesAnalyzed !== identity.filesAnalyzed ||
		supplied.scopeMode !== identity.scopeMode
	) {
		throw new Error("sniff_report target kind, label, baseRef, filesAnalyzed, and scopeMode must match the authenticated manifest target");
	}
	return { ...supplied, ...identity };
}

function normalizedFindingPath(value: string): string {
	if (isAbsolute(value) || value.includes("\\") || value.split("/").some((part) => part === "..")) {
		throw new Error("sniff report finding path must be a normalized relative path");
	}
	const normalized = value.replace(/^\.\//, "");
	if (!normalized || normalized === "." || normalized.split("/").some((part) => part === "" || part === ".")) {
		throw new Error("sniff report finding path must be a normalized relative path");
	}
	return normalized;
}

function validateFindingPaths(manifest: RunManifest, report: ReportInput): void {
	const allowed = new Set(manifest.resolvedTarget.files);
	for (const finding of report.findings) {
		const path = normalizedFindingPath(finding.location.path);
		if (!allowed.has(path)) throw new Error(`sniff report finding path is outside the authenticated target: ${path}`);
	}
}

type PlannedDirectory = { readonly lexical: string; readonly canonical: string };

function existingStat(path: string): ReturnType<typeof lstatSync> | undefined {
	try {
		return lstatSync(path);
	} catch (error) {
		if ((error as { code?: string }).code === "ENOENT") return undefined;
		throw error;
	}
}

function plannedDirectory(directory: string): PlannedDirectory {
	const lexical = resolve(directory);
	const root = parse(lexical).root;
	let current = root;
	let firstMissing: string | undefined;
	for (const component of lexical.slice(root.length).split(sep).filter(Boolean)) {
		current = join(current, component);
		const stat = existingStat(current);
		if (!stat) {
			firstMissing ??= current;
			continue;
		}
		if (stat.isSymbolicLink()) throw new Error("sniff report output directory cannot traverse a symlink");
		if (!stat.isDirectory()) throw new Error("sniff report output path must be a directory");
		if (firstMissing) continue;
	}
	const existing = firstMissing ? dirname(firstMissing) : lexical;
	const canonicalExisting = realpathSync(existing);
	const canonical = resolve(canonicalExisting, relative(existing, lexical));
	return { lexical, canonical };
}

function createSafeDirectory(planned: PlannedDirectory): string {
	const root = parse(planned.lexical).root;
	let current = root;
	for (const component of planned.lexical.slice(root.length).split(sep).filter(Boolean)) {
		current = join(current, component);
		if (!existingStat(current)) {
			try {
				mkdirSync(current);
			} catch (error) {
				if ((error as { code?: string }).code !== "EEXIST") throw error;
			}
		}
		const stat = existingStat(current);
		if (!stat || stat.isSymbolicLink()) throw new Error("sniff report output directory cannot traverse a symlink");
		if (!stat.isDirectory()) throw new Error("sniff report output path must be a directory");
	}
	const canonical = realpathSync(planned.lexical);
	if (canonical !== planned.canonical) throw new Error("sniff report output directory escaped its authorized destination");
	return canonical;
}

function saveDigest(request: Omit<SaveAuthorizationRequest, "digest">): string {
	return createHash("sha256")
		.update(
			JSON.stringify(request, (_, value) =>
				value && typeof value === "object" && !Array.isArray(value)
					? Object.fromEntries(Object.entries(value).sort(([a], [b]) => a.localeCompare(b)))
					: value,
			),
		)
		.digest("hex");
}

export async function runSniffReportTool(options: SniffReportToolOptions): Promise<SniffReportToolResult> {
	try {
		const suppliedManifest = options.report.extensions["sniff.intake"];
		if (suppliedManifest === undefined) throw new Error("sniff_report requires the issued sniff.intake manifest extension");
		const manifest = validateReportManifest(options.capability, options.manifestId, suppliedManifest);
		validateFindingPaths(manifest, options.report);
		validateReportCoverage(options.capability, options.manifestId, options.report.coverage);
		if (options.mode === "save" && !options.path?.trim()) throw new Error("sniff_report mode=save requires path");
		const report = buildSniffReport({
			...options.report,
			target: authenticatedTarget(manifest, options.report.target),
			extensions: { ...options.report.extensions, "sniff.intake": manifest },
		});
		const artifacts = createReportArtifacts(report);
		if (options.mode !== "save") return { artifacts, savedPaths: [] };
		if (options.runtime === undefined) throw new Error("sniff_report mode=save requires a trusted save authorization boundary");
		const planned = plannedDirectory(options.path ?? "");
		const files = [`${report.reportId}.json`, `${report.reportId}.md`, `${report.reportId}.receipt.json`];
		const unsigned = { directory: planned.canonical, manifestId: manifest.manifestId, reportId: report.reportId, files, manifest };
		const request = { ...unsigned, digest: saveDigest(unsigned) };
		const approval = await options.runtime.authorizeSave(request);
		if (!approval || approval.acceptedDigest !== request.digest) throw new Error("Sniff report save authorization was denied or mismatched");
		const directory = createSafeDirectory(planned);
		return { artifacts, savedPaths: saveReportArtifacts(artifacts, directory) };
	} finally {
		finalizeRunLease(options.capability, options.manifestId);
	}
}
