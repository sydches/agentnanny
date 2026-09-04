import { describe, it, expect } from 'vitest'

import {
  evaluateOpencodeTool,
  mapToolName,
  extractPrimaryInput,
  globToRegex,
  matchesPatternList,
  expandGroups,
  builtinGroups,
  type Policy,
} from '../lib/agentnanny-core.ts'

function makePolicy(overrides: Partial<Policy> = {}): Policy {
  return {
    scope_id: 'abc12345',
    created: new Date().toISOString(),
    ttl_seconds: 0,
    allow_groups: [],
    allow_tools: [],
    deny: [],
    _global_deny: [],
    ...overrides,
  }
}

describe('mapToolName', () => {
  it('maps lowercase opencode tools to PascalCase agentnanny vocabulary', () => {
    expect(mapToolName('bash')).toBe('Bash')
    expect(mapToolName('edit')).toBe('Edit')
    expect(mapToolName('write')).toBe('Write')
    expect(mapToolName('read')).toBe('Read')
    expect(mapToolName('glob')).toBe('Glob')
    expect(mapToolName('grep')).toBe('Grep')
    expect(mapToolName('webfetch')).toBe('WebFetch')
    expect(mapToolName('websearch')).toBe('WebSearch')
    expect(mapToolName('list')).toBe('Glob')
    expect(mapToolName('task')).toBe('Task')
    expect(mapToolName('todowrite')).toBe('TodoWrite')
    expect(mapToolName('todoread')).toBe('TodoRead')
    expect(mapToolName('question')).toBe('Question')
    expect(mapToolName('skill')).toBe('Skill')
  })

  it('capitalizes unknown tools as a fallback', () => {
    // Deliberate shape: unknown tools stay unmatchable against Python-side
    // PascalCase rules and fall to the static baseline (see mapToolName).
    expect(mapToolName('mytool')).toBe('Mytool')
    expect(mapToolName('some_tool')).toBe('Some_tool')
  })
})

describe('extractPrimaryInput', () => {
  it('uses command for Bash', () => {
    expect(extractPrimaryInput('Bash', { command: 'ls -la' })).toBe('ls -la')
  })
  it('uses filePath for Write/Edit/Read', () => {
    expect(extractPrimaryInput('Write', { filePath: '/tmp/x' })).toBe('/tmp/x')
    expect(extractPrimaryInput('Edit', { filePath: '/tmp/y' })).toBe('/tmp/y')
    expect(extractPrimaryInput('Read', { filePath: '/tmp/z' })).toBe('/tmp/z')
  })
  it('uses url for WebFetch', () => {
    expect(extractPrimaryInput('WebFetch', { url: 'https://x' })).toBe('https://x')
  })
  it('falls back to joining all values, stringified like Python', () => {
    expect(extractPrimaryInput('Something', { a: 'foo', b: 'bar' })).toBe('foo bar')
    expect(extractPrimaryInput('Something', { a: 'foo', n: 42 })).toBe('foo 42')
  })
  it('returns empty string for empty args', () => {
    expect(extractPrimaryInput('Bash', {})).toBe('')
  })
})

describe('globToRegex', () => {
  it('escapes dots and converts * to .*', () => {
    const re = globToRegex('rm*')
    expect(re.test('rm -rf /')).toBe(true)
    expect(re.test('rmdir')).toBe(true)
    expect(re.test('cat rm')).toBe(false)
  })

  it('handles alternation with |', () => {
    const re = globToRegex('curl*|wget*')
    expect(re.test('curl https://x')).toBe(true)
    expect(re.test('wget https://x')).toBe(true)
    expect(re.test('cat x')).toBe(false)
  })

  it('escapes regex metacharacters in the literal portion', () => {
    const re = globToRegex('git push --force*')
    expect(re.test('git push --force origin main')).toBe(true)
    expect(re.test('git pushX--force')).toBe(false)
  })
})

describe('matchesPatternList', () => {
  it('matches exact tool name', () => {
    expect(matchesPatternList('Bash', {}, ['Bash'])).toBe(true)
    expect(matchesPatternList('Read', {}, ['Bash'])).toBe(false)
  })

  it('matches tool(input) glob patterns against the primary input', () => {
    expect(matchesPatternList('Bash', { command: 'rm -rf /' }, ['Bash(rm*)'])).toBe(true)
    expect(matchesPatternList('Bash', { command: 'ls -la' }, ['Bash(rm*)'])).toBe(false)
  })

  it('matches wildcard .* against tool name', () => {
    expect(matchesPatternList('WebFetch', {}, ['.*'])).toBe(true)
    expect(matchesPatternList('Read', {}, ['.*Fetch.*'])).toBe(false)
  })

  it('returns false for empty pattern list', () => {
    expect(matchesPatternList('Bash', { command: 'rm' }, [])).toBe(false)
  })

  it('does not match when tool differs', () => {
    expect(matchesPatternList('Read', { filePath: '/etc/x' }, ['Bash(rm*)'])).toBe(false)
  })
})

describe('expandGroups', () => {
  it('expands filesystem group', () => {
    const patterns = expandGroups(['filesystem'])
    expect(patterns).toContain('Read')
    expect(patterns).toContain('Write')
    expect(patterns).toContain('Edit')
    expect(patterns).toContain('Glob')
    expect(patterns).toContain('Grep')
  })

  it('expands safe-shell group', () => {
    const patterns = expandGroups(['safe-shell'])
    expect(patterns).toContain('Bash(ls*)')
    expect(patterns).toContain('Bash(cat*)')
  })

  it('throws on unknown group', () => {
    expect(() => expandGroups(['nonexistent-group'])).toThrow(/Unknown group/)
  })

  it('returns empty array for no groups', () => {
    expect(expandGroups([])).toEqual([])
  })

  it('builtin groups table matches python (full table — drift in any group fails)', () => {
    // Mirrors BUILTIN_GROUPS in python_scio/third_party/agentnanny/agentnanny.py.
    expect(builtinGroups).toEqual({
      'read-only': ['Read', 'Glob', 'Grep'],
      write: ['Write', 'Edit'],
      filesystem: ['Read', 'Write', 'Edit', 'Glob', 'Grep'],
      shell: ['Bash'],
      'safe-shell': ['Bash(ls*)', 'Bash(cat*)', 'Bash(head*)', 'Bash(grep*)', 'Bash(find*)'],
      'review-shell': ['Bash(git log*)', 'Bash(git diff*)', 'Bash(git show*)', 'Bash(git blame*)'],
      network: ['WebFetch', 'WebSearch'],
      all: ['.*'],
    })
  })
})

describe('evaluateOpencodeTool', () => {
  it('returns passthrough when policy is null', () => {
    expect(evaluateOpencodeTool('bash', { command: 'rm -rf /' }, null)).toEqual({
      verdict: 'passthrough',
      reason: expect.stringContaining('no policy'),
    })
  })

  it('denies on global deny match', () => {
    const policy = makePolicy({ _global_deny: ['Bash(rm*)'] })
    const result = evaluateOpencodeTool('bash', { command: 'rm -rf /tmp/x' }, policy)
    expect(result.verdict).toBe('deny')
    expect(result.reason).toMatch(/global deny/)
  })

  it('global deny beats session allow', () => {
    const policy = makePolicy({
      _global_deny: ['Bash(rm*)'],
      allow_tools: ['Bash'],
    })
    expect(evaluateOpencodeTool('bash', { command: 'rm -rf /tmp/x' }, policy).verdict).toBe('deny')
  })

  it('denies on session deny match', () => {
    const policy = makePolicy({ deny: ['Bash(git push --force*)'] })
    expect(evaluateOpencodeTool('bash', { command: 'git push --force origin main' }, policy).verdict).toBe('deny')
  })

  it('session deny beats session allow', () => {
    const policy = makePolicy({
      deny: ['Bash(rm*)'],
      allow_tools: ['Bash'],
    })
    expect(evaluateOpencodeTool('bash', { command: 'rm -rf /tmp/x' }, policy).verdict).toBe('deny')
  })

  it('allows when tool matches allow_tools', () => {
    const policy = makePolicy({ allow_tools: ['Read'] })
    expect(evaluateOpencodeTool('read', { filePath: '/tmp/x' }, policy).verdict).toBe('allow')
  })

  it('allows when tool matches an expanded allow group', () => {
    const policy = makePolicy({ allow_groups: ['filesystem'] })
    expect(evaluateOpencodeTool('read', { filePath: '/tmp/x' }, policy).verdict).toBe('allow')
    expect(evaluateOpencodeTool('write', { filePath: '/tmp/x' }, policy).verdict).toBe('allow')
  })

  it('allows via safe-shell group glob match', () => {
    const policy = makePolicy({ allow_groups: ['safe-shell'] })
    expect(evaluateOpencodeTool('bash', { command: 'ls -la' }, policy).verdict).toBe('allow')
    expect(evaluateOpencodeTool('bash', { command: 'rm -rf /' }, policy).verdict).toBe('passthrough')
  })

  it('returns passthrough for unmatched op', () => {
    const policy = makePolicy({ allow_tools: ['Read'] })
    expect(evaluateOpencodeTool('bash', { command: 'curl https://x' }, policy).verdict).toBe('passthrough')
  })
})
