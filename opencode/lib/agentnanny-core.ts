/**
 * agentnanny core — session-policy evaluation shared by the OpenCode plugin
 * entry (agentnanny.ts) and its tests.
 *
 * Session file: ${AGENTNANNY_SESSION_DIR || os.tmpdir()}/agentnanny/sessions/<scope>.json
 * Audit log:   ${AGENTNANNY_LOG || '/tmp/agentnanny.log'}  (TSV, 5 fields)
 */

import { existsSync, readFileSync, unlinkSync, renameSync, statSync, appendFileSync, mkdirSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'

export type Policy = {
  scope_id: string
  created: string // ISO-8601
  ttl_seconds: number
  allow_groups: string[]
  allow_tools: string[]
  deny: string[]
  _global_deny: string[]
  _profile_name?: string
}

export type Verdict = 'allow' | 'deny' | 'passthrough'

export type EvalResult = {
  verdict: Verdict
  reason: string
}

// Builtin groups — must mirror python_scio/third_party/agentnanny/agentnanny.py
// (BUILTIN_GROUPS). Custom groups from config.toml are NOT expanded here.
export const builtinGroups: Record<string, string[]> = {
  'read-only': ['Read', 'Glob', 'Grep'],
  write: ['Write', 'Edit'],
  filesystem: ['Read', 'Write', 'Edit', 'Glob', 'Grep'],
  shell: ['Bash'],
  'safe-shell': ['Bash(ls*)', 'Bash(cat*)', 'Bash(head*)', 'Bash(grep*)', 'Bash(find*)'],
  'review-shell': ['Bash(git log*)', 'Bash(git diff*)', 'Bash(git show*)', 'Bash(git blame*)'],
  network: ['WebFetch', 'WebSearch'],
  all: ['.*'],
}

// Tool name mapping (OpenCode lowercase -> agentnanny PascalCase)
const toolMap: Record<string, string> = {
  bash: 'Bash',
  edit: 'Edit',
  write: 'Write',
  read: 'Read',
  glob: 'Glob',
  grep: 'Grep',
  webfetch: 'WebFetch',
  websearch: 'WebSearch',
  list: 'Glob',
  task: 'Task',
  todowrite: 'TodoWrite',
  todoread: 'TodoRead',
  question: 'Question',
  skill: 'Skill',
}

export function mapToolName(opencodeTool: string): string {
  const mapped = toolMap[opencodeTool.toLowerCase()]
  if (mapped) return mapped
  if (!opencodeTool) return opencodeTool
  // Unknown tools capitalize only the first char ('some_tool' -> 'Some_tool'), so
  // they can never match a Python-side PascalCase rule. Deliberate: an unmapped
  // OpenCode tool is unmanaged by agentnanny and falls to the static baseline.
  return opencodeTool.charAt(0).toUpperCase() + opencodeTool.slice(1)
}

// Primary input extraction — mirrors Python `_primary_input`
export function extractPrimaryInput(tool: string, args: unknown): string {
  if (!args || typeof args !== 'object') return ''
  const a = args as Record<string, unknown>
  if (tool === 'Bash') return String(a.command ?? '')
  if (tool === 'Write' || tool === 'Edit' || tool === 'Read') return String(a.filePath ?? a.file_path ?? '')
  if (tool === 'WebFetch') return String(a.url ?? '')
  return Object.values(a).map(String).join(' ')
}

// Glob -> regex — mirrors Python `_glob_to_regex`

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

export function globToRegex(pattern: string): RegExp {
  const segments = pattern.split('|').map((seg) => {
    const escaped = escapeRegex(seg)
    return escaped.replace(/\\\*/g, '.*').replace(/\\\?/g, '.')
  })
  return new RegExp(`^(?:${segments.join('|')})`)
}

// Pattern list matching — mirrors Python `matches_deny` / `matches_allow`

export function matchesPatternList(tool: string, args: unknown, patterns: string[]): boolean {
  for (const pattern of patterns) {
    const m = /^(\w+)\((.+)\)$/.exec(pattern)
    if (m) {
      const [, patTool, patInput] = m
      if (patTool !== tool) continue
      const inputStr = extractPrimaryInput(tool, args)
      if (globToRegex(patInput).test(inputStr)) return true
    } else {
      if (pattern === tool) return true
      try {
        if (new RegExp(`^${pattern}$`).test(tool)) return true
      } catch {
        // invalid regex, skip
      }
    }
  }
  return false
}

export function expandGroups(groupNames: string[]): string[] {
  const patterns: string[] = []
  for (const name of groupNames) {
    const group = builtinGroups[name]
    if (!group) throw new Error(`Unknown group: ${name}`)
    patterns.push(...group)
  }
  return patterns
}

const scopeIdRe = /^[a-f0-9]{8}$/

function sessionDir(): string {
  // AGENTNANNY_SESSION_DIR exists for tests only. Python has no such override —
  // honoring it in production would split the write (activate) and read
  // (plugin) paths, silently disabling enforcement. Gate on the test-runner
  // marker so a stray AGENTNANNY_SESSION_DIR in a real shell stays inert.
  const isTest = process.env.BUN_TEST === 'true' || process.env.VITEST === 'true'
  if (isTest && process.env.AGENTNANNY_SESSION_DIR) {
    return process.env.AGENTNANNY_SESSION_DIR
  }
  return join(tmpdir(), 'agentnanny', 'sessions')
}

function isPolicyShape(value: unknown): value is Policy {
  if (!value || typeof value !== 'object') return false
  const v = value as Record<string, unknown>
  return (
    typeof v.scope_id === 'string' &&
    typeof v.created === 'string' &&
    typeof v.ttl_seconds === 'number' &&
    Array.isArray(v.allow_groups) &&
    Array.isArray(v.allow_tools) &&
    Array.isArray(v.deny)
  )
}

export function loadPolicy(scopeId: string | undefined): Policy | null {
  if (!scopeId) return null
  if (!scopeIdRe.test(scopeId)) return null

  const path = join(sessionDir(), `${scopeId}.json`)
  if (!existsSync(path)) return null

  let raw: string
  try {
    raw = readFileSync(path, 'utf-8')
  } catch {
    return null
  }
  if (!raw.trim()) return null

  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch {
    return null
  }
  if (!isPolicyShape(parsed)) return null
  if (parsed.scope_id !== scopeId) return null

  // TTL expiry — treat as no scope and clean up the stale file (matches Python).
  if (parsed.ttl_seconds > 0) {
    const created = Date.parse(parsed.created)
    if (!Number.isNaN(created)) {
      const elapsedSec = (Date.now() - created) / 1000
      if (elapsedSec > parsed.ttl_seconds) {
        try {
          unlinkSync(path)
        } catch {
          // best-effort cleanup
        }
        return null
      }
    }
  }

  return parsed
}

// Evaluation — preserves Python `evaluate_policy` order:
//   global deny -> session deny -> session allow -> passthrough

export function evaluateOpencodeTool(opencodeTool: string, args: unknown, policy: Policy | null): EvalResult {
  if (!policy) {
    return { verdict: 'passthrough', reason: 'no policy (no active scope or expired)' }
  }
  const tool = mapToolName(opencodeTool)

  if (matchesPatternList(tool, args, policy._global_deny ?? [])) {
    return { verdict: 'deny', reason: `blocked by global deny list` }
  }

  if (matchesPatternList(tool, args, policy.deny ?? [])) {
    return { verdict: 'deny', reason: `blocked by session deny list (scope ${policy.scope_id})` }
  }

  let allowPatterns: string[] = [...(policy.allow_tools ?? [])]
  const groupNames = policy.allow_groups ?? []
  if (groupNames.length > 0) {
    try {
      allowPatterns = allowPatterns.concat(expandGroups(groupNames))
    } catch (err) {
      return { verdict: 'passthrough', reason: `group resolution failed: ${err}` }
    }
  }

  if (matchesPatternList(tool, args, allowPatterns)) {
    return { verdict: 'allow', reason: `${tool} allowed by session policy (scope ${policy.scope_id})` }
  }

  return { verdict: 'passthrough', reason: `${tool} not in session allow list (scope ${policy.scope_id})` }
}

// Audit logging — TSV, same shape as Python audit_log

const auditSource = 'opencode-plugin'
const auditLogMaxBytes = 10 * 1024 * 1024

function auditLogPath(): string {
  return process.env.AGENTNANNY_LOG ?? '/tmp/agentnanny.log'
}

// Byte-parity with Python's isoformat(timespec='seconds'): 2026-09-04T11:00:00+00:00
function auditTimestamp(): string {
  return `${new Date().toISOString().slice(0, 19)}+00:00`
}

// Coarse single-backup rotation — mirrors Python's `_rotate_log` threshold so
// pure-OpenCode sessions don't grow the log forever.
function rotateAuditLog(path: string): void {
  try {
    if (statSync(path).size >= auditLogMaxBytes) renameSync(path, `${path}.1`)
  } catch {
    // best-effort
  }
}

export function auditLog(action: 'allowed' | 'denied', tool: string, detail: string): void {
  const line = `${auditTimestamp()}\t${auditSource}\t${action}\t${tool}\t${detail.slice(0, 200)}\n`
  try {
    const path = auditLogPath()
    mkdirSync(dirname(path), { recursive: true })
    rotateAuditLog(path)
    appendFileSync(path, line, { mode: 0o600 })
  } catch {
    // Log failure is not fatal
  }
}
