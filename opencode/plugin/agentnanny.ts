/**
 * agentnanny OpenCode plugin entry — enforces the active Agent Nanny session
 * policy inside OpenCode via the `tool.execute.before` and `permission.ask`
 * hooks. All policy logic lives in agentnanny-core.ts; this file only wires
 * the hooks.
 *
 * This module must default-export the plugin function and nothing else:
 * OpenCode's legacy plugin loader (getLegacyPlugins) iterates every runtime
 * export and throws "Plugin export is not a function" on the first
 * non-function, which would silently disable the plugin.
 *
 * With no AGENTNANNY_SCOPE / no session file the plugin is a no-op and the
 * static `opencode.json` permission policy continues to govern.
 */

import type { Plugin } from '@opencode-ai/plugin'
import { auditLog, evaluateOpencodeTool, extractPrimaryInput, loadPolicy, mapToolName } from './lib/agentnanny-core.ts'

const AgentNannyPlugin: Plugin = async () => {
  // Cache allow verdicts per callID so `permission.ask` can short-circuit the
  // prompt for ops we already approved at `tool.execute.before`. Entries are
  // single-use (deleted on read) so the map can't grow unbounded over a long
  // session. Deny verdicts are not cached: the before-hook throws on deny, so
  // permission.ask never fires for them.
  //
  // Correctness depends on OpenCode firing `tool.execute.before` before
  // `permission.ask` with a stable callID for prompted tools. If that ever
  // breaks, the cache misses and the op degrades to the fallback
  // re-evaluation below — the safe direction.
  const allowByCallId = new Map<string, true>()

  return {
    'tool.execute.before': async (input, output) => {
      try {
        const policy = loadPolicy(process.env.AGENTNANNY_SCOPE)
        if (!policy) return
        const { verdict, reason } = evaluateOpencodeTool(input.tool, output.args, policy)
        const tool = mapToolName(input.tool)
        if (verdict === 'deny') {
          const detail = extractPrimaryInput(tool, output.args)
          auditLog('denied', tool, detail)
          throw new Error(`agentnanny: ${reason}`)
        }
        if (verdict === 'allow') {
          if (input.callID) allowByCallId.set(input.callID, true)
          const detail = extractPrimaryInput(tool, output.args)
          auditLog('allowed', tool, detail)
        }
        // passthrough: no log, fall through to opencode.json static policy
      } catch (err) {
        // Never break the tool — but DO propagate the deny throw
        if (err instanceof Error && err.message.startsWith('agentnanny:')) throw err
      }
    },

    'permission.ask': async (input, output) => {
      try {
        if (!process.env.AGENTNANNY_SCOPE) return
        // Fast path: we already approved this call at tool.execute.before.
        // The before-hook already audit-logged the allow, so don't re-log.
        if (input.callID && allowByCallId.delete(input.callID)) {
          output.status = 'allow'
          return
        }
        // Fallback: callID didn't match (hook ordering, different callID
        // assignment, etc.) — re-evaluate from the Permission object itself.
        // For bash the command is carried in `pattern` (a string or string[]),
        // while `metadata` is the tool's passthrough ({} for bash) — so build
        // the eval args from pattern when metadata yields no primary input.
        const policy = loadPolicy(process.env.AGENTNANNY_SCOPE)
        if (!policy) return
        const tool = mapToolName(input.type)
        // opencode may pass the internal PermissionV1 shape with `patterns`
        // (plural array) instead of the SDK's `pattern` (singular). Handle both.
        const patternValue = (input as Record<string, unknown>).patterns ?? input.pattern
        const metadataArgs = input.metadata as Record<string, unknown>
        let args: unknown = metadataArgs
        if (extractPrimaryInput(tool, metadataArgs) === '' && patternValue) {
          const patternStr = Array.isArray(patternValue) ? patternValue.join(' ') : String(patternValue)
          // `command` for Bash so extractPrimaryInput picks it up; harmless for
          // other tools since they read their own keys first.
          args = { ...metadataArgs, command: patternStr }
        }
        const detail = extractPrimaryInput(tool, args)
        const { verdict } = evaluateOpencodeTool(input.type, args, policy)
        if (verdict === 'allow') {
          output.status = 'allow'
          auditLog('allowed', tool, detail)
        } else if (verdict === 'deny') {
          output.status = 'deny'
          auditLog('denied', tool, detail)
        }
        // passthrough: leave output.status as 'ask'
      } catch {
        // swallow — never crash the permission flow
      }
    },
  }
}

export default AgentNannyPlugin
