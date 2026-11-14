export type AlertMode = "warning" | "error" | "none"

// An absent or invalid option keeps the alert on: a typo must not silently
// remove the only sign that tools run unsandboxed.
export function alertMode(options: Readonly<Record<string, unknown>> | undefined): AlertMode {
  const value = options?.alert
  return value === "warning" || value === "error" || value === "none" ? value : "warning"
}
