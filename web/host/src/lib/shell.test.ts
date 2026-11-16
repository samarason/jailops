import { describe, expect, it } from 'vitest'
import { Screen, xtermColor } from './vt100'
import { ALL_KEYS } from './configKeys'

describe('the prompt of a jail in the console terminal', () => {
  it('maps the 256 colours of xterm', () => {
    expect(xtermColor(1)).toBe('#c91b00')
    expect(xtermColor(16)).toBe('#000000')
    expect(xtermColor(39)).toBe('#00afff') // the default prompt of a jail
    expect(xtermColor(40)).toBe('#00d700') // the green of a host
    expect(xtermColor(196)).toBe('#ff0000')
    expect(xtermColor(231)).toBe('#ffffff')
    expect(xtermColor(232)).toBe('#080808')
    expect(xtermColor(255)).toBe('#eeeeee')
    expect(xtermColor(-1)).toBeUndefined()
    expect(xtermColor(256)).toBeUndefined()
  })
  it('paints the default prompt as bash prints it', () => {
    const s = new Screen(30, 2)
    // bash leaves \x01 and \x02 out of what it prints: the terminal gets the plain sequences
    s.write('\x1b[38;5;39mroot@web:/#\x1b[0m ls')
    const row = s.grid[0]
    expect(row.slice(0, 11).map((c) => c.ch).join('')).toBe('root@web:/#')
    expect(row[0].fg).toBe(39)
    expect(row[10].fg).toBe(39)
    expect(row[12].fg).toBe(-1)
  })
  it('the registry has the shell and prompt keys with their help', () => {
    const prompt = ALL_KEYS.find((k) => k.name === 'prompt')
    expect(prompt?.type).toBe('string')
    expect(prompt?.restart_required).toBe(false)
    expect(prompt?.description).toContain('~/.bashrc wins')
    expect(ALL_KEYS.find((k) => k.name === 'shell')?.example).toBe('bash')
  })
})
