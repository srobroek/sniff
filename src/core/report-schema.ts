import Ajv2020, { type ErrorObject } from "ajv/dist/2020.js";
import reportSchema from "../../skills/sniff/references/report.schema.json" with { type: "json" };
import reportInputSchema from "../../skills/sniff/references/report-input.schema.json" with { type: "json" };
import type { ReportInput, SniffReport } from "./report.ts";

const RFC3339_UTC = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?Z$/;

function isCanonicalDateTime(value: string): boolean {
  const match = RFC3339_UTC.exec(value);
  if (!match) return false;
  const [, yearText, monthText, dayText, hourText, minuteText, secondText] = match;
  const parts = [yearText, monthText, dayText, hourText, minuteText, secondText];
  if (parts.some((part) => part === undefined)) return false;
  const [year, month, day, hour, minute, second] = parts.map(Number) as [number, number, number, number, number, number];
  if (month < 1 || month > 12 || hour > 23 || minute > 59 || second > 59) return false;
  const date = new Date(Date.UTC(year, month - 1, day, hour, minute, second));
  return date.getUTCFullYear() === year && date.getUTCMonth() === month - 1 && date.getUTCDate() === day;
}

const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false });
ajv.addFormat("date-time", { type: "string", validate: isCanonicalDateTime });
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
