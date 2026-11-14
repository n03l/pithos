import assert from "node:assert/strict"
import test from "node:test"
import { alertMode } from "./alert.ts"

test("alertMode reads the configured level", () => {
  assert.equal(alertMode({ alert: "warning" }), "warning")
  assert.equal(alertMode({ alert: "error" }), "error")
  assert.equal(alertMode({ alert: "none" }), "none")
})

test("alertMode stays on for missing or hostile values", () => {
  assert.equal(alertMode(undefined), "warning")
  assert.equal(alertMode({}), "warning")
  assert.equal(alertMode({ alert: "WARNING" }), "warning")
  assert.equal(alertMode({ alert: 1 }), "warning")
  assert.equal(alertMode({ alert: null }), "warning")
  assert.equal(alertMode({ alert: "__proto__" }), "warning")
})
