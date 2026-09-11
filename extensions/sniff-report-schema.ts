import Ajv2020, { type ErrorObject } from "ajv/dist/2020.js";
import reportSchema from "../skills/sniff/references/report.schema.json" with { type: "json" };
import reportInputSchema from "../skills/sniff/references/report-input.schema.json" with { type: "json" };
import type { ReportInput, SniffReport } from "./sniff-report.ts";

const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false });
const validateReportInputSchema = ajv.compile(reportInputSchema);
const validateReportSchema = ajv.compile(reportSchema);

function validationMessage(errors: ErrorObject[] | null | undefined): string {
  return (errors ?? [])
    .map((error) => `${error.instancePath || "/"} ${error.message ?? "is invalid"}`)
    .join("; ");
}

export function assertReportInput(value: unknown): asserts value is ReportInput {
  if (!validateReportInputSchema(value)) {
    throw new Error(`Invalid Sniff report input: ${validationMessage(validateReportInputSchema.errors)}`);
  }
}

export function assertSniffReportSchema(value: unknown): asserts value is SniffReport {
  if (!validateReportSchema(value)) {
    throw new Error(`Invalid Sniff report schema: ${validationMessage(validateReportSchema.errors)}`);
  }
}
