// A small VT100 subset for the exec terminal: printable text, CR LF BS TAB BEL, cursor movement
// (CSI A B C D H f G d), erase (J K), SGR colours and bold/underline/reverse, scrolling. No alternate
// screen, no mouse: a full-screen program shows as plain text and a line-mode shell works as expected.

export interface Cell { ch: string; fg: number; bg: number; bold: boolean; ul: boolean; rev: boolean }

const BASE16 = ['#000', '#c91b00', '#00c200', '#c7c400', '#2225c4', '#c930c7', '#00c5c7', '#c7c7c7', '#686868', '#ff6e67', '#5ffa68', '#fffc67', '#6871ff', '#ff77ff', '#60fdff', '#fff']
const hex2 = (n: number) => n.toString(16).padStart(2, '0')

/** The colour of an SGR colour number (30-37/90-97 as 0-15, or 38;5;N): the 16 base colours, the 6x6x6 cube
 *  (16-231) and the grey ramp (232-255) of xterm. The default prompt of a jail is 38;5;39, a light blue. */
export function xtermColor(n: number): string | undefined {
  if (!Number.isInteger(n) || n < 0 || n > 255) return undefined
  if (n < 16) return BASE16[n]
  if (n < 232) {
    const v = [0, 95, 135, 175, 215, 255]
    const i = n - 16
    return '#' + hex2(v[Math.floor(i / 36)]) + hex2(v[Math.floor(i / 6) % 6]) + hex2(v[i % 6])
  }
  const g = 8 + (n - 232) * 10
  return '#' + hex2(g) + hex2(g) + hex2(g)
}
const blank = (): Cell => ({ ch: ' ', fg: -1, bg: -1, bold: false, ul: false, rev: false })

export class Screen {
  cols: number
  rows: number
  grid: Cell[][]
  x = 0
  y = 0
  /** Lines that scrolled off the top, newest last, bounded. */
  scrollback: string[] = []
  private pen = { fg: -1, bg: -1, bold: false, ul: false, rev: false }
  private state: 'ground' | 'esc' | 'csi' | 'osc' = 'ground'
  private params = ''
  private wrapPending = false
  private dec = new TextDecoder('utf-8')

  constructor(cols = 80, rows = 24, private maxScrollback = 1000) {
    this.cols = cols
    this.rows = rows
    this.grid = Array.from({ length: rows }, () => Array.from({ length: cols }, blank))
  }

  resize(cols: number, rows: number): void {
    cols = Math.max(2, cols)
    rows = Math.max(1, rows)
    const g = Array.from({ length: rows }, (_, r) => Array.from({ length: cols }, (_, c) => this.grid[r]?.[c] ?? blank()))
    this.grid = g
    this.cols = cols
    this.rows = rows
    this.x = Math.min(this.x, cols - 1)
    this.y = Math.min(this.y, rows - 1)
  }

  write(data: Uint8Array | string): void {
    const text = typeof data === 'string' ? data : this.dec.decode(data, { stream: true })
    for (const ch of text) this.put(ch)
  }

  private put(ch: string): void {
    const code = ch.codePointAt(0)!
    switch (this.state) {
      case 'esc':
        if (ch === '[') { this.state = 'csi'; this.params = ''; return }
        if (ch === ']') { this.state = 'osc'; return }
        this.state = 'ground'
        if (ch === 'c') this.reset()
        if (ch === 'M') this.reverseIndex()
        return
      case 'osc':
        if (code === 7 || code === 0x9c || ch === '\\') this.state = 'ground'
        return
      case 'csi':
        if ((code >= 0x30 && code <= 0x3f) || code === 0x20) { this.params += ch; return }
        this.state = 'ground'
        this.csi(ch, this.params)
        return
    }
    if (code === 0x1b) { this.state = 'esc'; return }
    if (code === 13) { this.x = 0; this.wrapPending = false; return }
    if (code === 10 || code === 11 || code === 12) { this.lineFeed(); return }
    if (code === 8) { if (this.x > 0) this.x--; this.wrapPending = false; return }
    if (code === 9) { this.x = Math.min(this.cols - 1, (this.x + 8) & ~7); return }
    if (code < 32 || code === 127) return
    if (this.wrapPending) { this.x = 0; this.lineFeed(); this.wrapPending = false }
    this.grid[this.y][this.x] = { ch, ...this.pen }
    if (this.x === this.cols - 1) this.wrapPending = true
    else this.x++
  }

  private lineFeed(): void {
    if (this.y === this.rows - 1) this.scrollUp()
    else this.y++
  }
  private reverseIndex(): void {
    if (this.y === 0) {
      this.grid.pop()
      this.grid.unshift(Array.from({ length: this.cols }, blank))
    } else this.y--
  }
  private scrollUp(): void {
    const top = this.grid.shift()!
    this.scrollback.push(top.map((c) => c.ch).join('').trimEnd())
    if (this.scrollback.length > this.maxScrollback) this.scrollback.shift()
    this.grid.push(Array.from({ length: this.cols }, blank))
  }
  private reset(): void {
    this.grid = Array.from({ length: this.rows }, () => Array.from({ length: this.cols }, blank))
    this.x = this.y = 0
    this.pen = { fg: -1, bg: -1, bold: false, ul: false, rev: false }
  }

  private csi(final: string, raw: string): void {
    const p = raw.replace(/[?>!]/g, '').split(';').map((x) => (x === '' ? NaN : Number(x)))
    const n = (i: number, d: number) => (Number.isNaN(p[i] ?? NaN) ? d : p[i])
    this.wrapPending = false
    switch (final) {
      case 'A': this.y = Math.max(0, this.y - Math.max(1, n(0, 1))); break
      case 'B': this.y = Math.min(this.rows - 1, this.y + Math.max(1, n(0, 1))); break
      case 'C': this.x = Math.min(this.cols - 1, this.x + Math.max(1, n(0, 1))); break
      case 'D': this.x = Math.max(0, this.x - Math.max(1, n(0, 1))); break
      case 'G': this.x = Math.min(this.cols - 1, Math.max(0, n(0, 1) - 1)); break
      case 'd': this.y = Math.min(this.rows - 1, Math.max(0, n(0, 1) - 1)); break
      case 'H': case 'f': this.y = Math.min(this.rows - 1, Math.max(0, n(0, 1) - 1)); this.x = Math.min(this.cols - 1, Math.max(0, n(1, 1) - 1)); break
      case 'J': {
        const mode = n(0, 0)
        if (mode === 2 || mode === 3) this.grid = Array.from({ length: this.rows }, () => Array.from({ length: this.cols }, blank))
        else if (mode === 0) { this.eraseLine(this.x, this.cols); for (let r = this.y + 1; r < this.rows; r++) this.grid[r] = Array.from({ length: this.cols }, blank) }
        else { for (let r = 0; r < this.y; r++) this.grid[r] = Array.from({ length: this.cols }, blank); this.eraseLine(0, this.x + 1) }
        break
      }
      case 'K': { const mode = n(0, 0); if (mode === 0) this.eraseLine(this.x, this.cols); else if (mode === 1) this.eraseLine(0, this.x + 1); else this.eraseLine(0, this.cols); break }
      case 'm': this.sgr(p.length ? p : [0]); break
      default: break // unsupported sequences are ignored, never printed
    }
  }
  private eraseLine(from: number, to: number): void {
    for (let c = from; c < Math.min(to, this.cols); c++) this.grid[this.y][c] = blank()
  }
  private sgr(p: number[]): void {
    for (let i = 0; i < p.length; i++) {
      const v = Number.isNaN(p[i]) ? 0 : p[i]
      if (v === 0) this.pen = { fg: -1, bg: -1, bold: false, ul: false, rev: false }
      else if (v === 1) this.pen.bold = true
      else if (v === 4) this.pen.ul = true
      else if (v === 7) this.pen.rev = true
      else if (v === 22) this.pen.bold = false
      else if (v === 24) this.pen.ul = false
      else if (v === 27) this.pen.rev = false
      else if (v >= 30 && v <= 37) this.pen.fg = v - 30
      else if (v >= 90 && v <= 97) this.pen.fg = v - 90 + 8
      else if (v === 39) this.pen.fg = -1
      else if (v >= 40 && v <= 47) this.pen.bg = v - 40
      else if (v >= 100 && v <= 107) this.pen.bg = v - 100 + 8
      else if (v === 49) this.pen.bg = -1
      else if ((v === 38 || v === 48) && p[i + 1] === 5) { if (v === 38) this.pen.fg = p[i + 2]; else this.pen.bg = p[i + 2]; i += 2 }
    }
  }

  /** The visible text, one line per row without trailing blanks. */
  text(): string {
    return this.grid.map((r) => r.map((c) => c.ch).join('').trimEnd()).join('\n').replace(/\n+$/, '')
  }
  /** Scrollback plus the screen, for Copy. */
  allText(): string {
    return [...this.scrollback, this.text()].join('\n')
  }
}

/** Keyboard event to the bytes a terminal sends. Returns null for keys the terminal ignores. */
export function keyToBytes(e: { key: string; ctrlKey: boolean; altKey: boolean; metaKey: boolean }): string | null {
  if (e.metaKey) return null
  const k = e.key
  const map: Record<string, string> = { Enter: '\r', Backspace: '\x7f', Tab: '\t', Escape: '\x1b', ArrowUp: '\x1b[A', ArrowDown: '\x1b[B', ArrowRight: '\x1b[C', ArrowLeft: '\x1b[D', Home: '\x1b[H', End: '\x1b[F', Delete: '\x1b[3~', PageUp: '\x1b[5~', PageDown: '\x1b[6~' }
  if (map[k]) return map[k]
  if (e.ctrlKey && k.length === 1) {
    const c = k.toLowerCase().charCodeAt(0)
    if (c >= 97 && c <= 122) return String.fromCharCode(c - 96)
    if (k === '[') return '\x1b'
    if (k === ' ') return '\0'
    return null
  }
  if (k.length === 1 || [...k].length === 1) return e.altKey ? '\x1b' + k : k
  return null
}
