/** @jsxImportSource @opentui/solid */
import { existsSync } from "node:fs"
import { Plugin } from "@opencode/plugin/tui"

// pithos sets PITHOS=1 and always mounts this file. Requiring both means a stray
// PITHOS=1 on the host still shows the open lock. Meant for `opencode --standalone`,
// where the TUI and the server (which runs the tools) share the sandbox.
const MARKER = "/run/pithos/blocked-hosts"

export function sandboxed(env: NodeJS.ProcessEnv = process.env, exists: (p: string) => boolean = existsSync) {
  return env.PITHOS === "1" && exists(MARKER)
}

export default Plugin.define({
  id: "pithos-lock.tui",
  setup(context) {
    const inside = sandboxed()
    const lock = () => {
      const color = inside ? context.theme.text.feedback.success.base : context.theme.text.feedback.error.base
      return (
        <text wrapMode="none" flexShrink={0}>
          {inside ? "🔒" : "🔓"}
          <span style={{ fg: color }}>●</span>
        </text>
      )
    }
    const disposeHome = context.ui.slot({ append: "home.footer.status", render: lock })
    const disposePrompt = context.ui.slot({ append: "prompt.footer.status", render: lock })
    return () => {
      disposeHome()
      disposePrompt()
    }
  },
})
