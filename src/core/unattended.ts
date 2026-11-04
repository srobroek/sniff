export const UNATTENDED_INTAKE_ENV = "SNIFF_UNATTENDED_INTAKE";

export const UNATTENDED_INTAKE_REQUIRED_MESSAGE = `Intake needs a person's confirmation and this host cannot ask for one. The operator can permit unattended intake by setting ${UNATTENDED_INTAKE_ENV}=1 in the server environment; tool arguments cannot.`;

export const UNATTENDED_INTAKE_REASON = `The operator enabled ${UNATTENDED_INTAKE_ENV} for the server hosting this exact intake digest.`;

/**
 * Whether the operator opted in to unattended intake. Read only from the server's own
 * environment; never derive it from tool arguments.
 */
export function unattendedIntakeAllowed(env: Readonly<Record<string, string | undefined>> = process.env): boolean {
	const value = env[UNATTENDED_INTAKE_ENV]?.trim().toLowerCase();
	return value === "1" || value === "true" || value === "yes";
}
