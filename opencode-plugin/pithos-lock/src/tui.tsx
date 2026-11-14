/** @jsxImportSource @opentui/solid */
import { existsSync } from "node:fs"
import { Plugin } from "@opencode/plugin/tui"
import { createSignal } from "solid-js"
import { alertMode } from "./alert.ts"

// pithos sets PITHOS=1 and always mounts this file. Requiring both means a stray
// PITHOS=1 on the host still shows the open lock. Meant for `opencode --standalone`,
// where the TUI and the server (which runs the tools) share the sandbox.
const MARKER = "/run/pithos/blocked-hosts"

const TITLE = "OpenCode is running outside the pithos sandbox"
const MESSAGE = "Tools run unsandboxed, with full network and file access. Restart opencode inside pithos to sandbox them."

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

    let closed = false
    // Lets the lock go if the plugin is removed or reloaded out of existence.
    let clearLock: (() => void) | undefined
    const mode = alertMode(context.options)

    if (!inside && mode === "warning") {
      void context.ui.dialog.alert({ title: TITLE, message: MESSAGE })
    }

    if (!inside && mode === "error") {
      const [shown, setShown] = createSignal(false)
      const show = () => {
        if (closed) return
        setShown(true)
        context.ui.dialog.show(
          () => (
            <box flexDirection="column" gap={1} paddingLeft={1} paddingRight={1}>
              <text fg={context.theme.text.feedback.error.base} wrapMode="word">
                {TITLE}
              </text>
              <text fg={context.theme.text.muted} wrapMode="word">
                {MESSAGE}
              </text>
              <text fg={context.theme.text.muted}>Press enter to quit.</text>
            </box>
          ),
          // Esc, ctrl+c and a backdrop click all close the dialog, and the escape
          // handler pops the stack after this returns: reopen once it has.
          () => {
            setShown(false)
            queueMicrotask(show)
          },
        )
        // show() replaces the stack and resets these, so size it afterwards.
        context.ui.dialog.set({ size: "large", centered: true })
      }
      // Enter only quits while the lock is up, so it cannot act on another plugin's dialog.
      context.keymap.layer(() => ({
        mode: "modal",
        enabled: () => shown(),
        commands: [
          {
            bind: "return",
            title: "Quit opencode",
            group: "pithos",
            run: () => {
              context.keymap.dispatch("app.exit")
              // The app restores the terminal on its own exit; if its command is gone, leave anyway.
              setTimeout(() => {
                context.renderer.destroy()
                process.exit(0)
              }, 1000)
            },
          },
        ],
      }))
      show()
      clearLock = () => context.ui.dialog.clear()
    }

    return () => {
      closed = true
      clearLock?.()
      disposeHome()
      disposePrompt()
    }
  },
})
