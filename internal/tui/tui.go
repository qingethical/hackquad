// Package tui is the interactive hacklith interface: a raw-mode
// terminal UI with a module panel, a streaming output panel and a
// target input bar. Stdlib only — termios via syscall, ANSI escapes
// for everything else.
package tui

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/qingethical/hacklith/internal/cli"
	"github.com/qingethical/hacklith/internal/modules"
	"github.com/qingethical/hacklith/internal/scanner"
)

const (
	altOn   = "\x1b[?1049h"
	altOff  = "\x1b[?1049l"
	hideCur = "\x1b[?25l"
	showCur = "\x1b[?25h"
	home    = "\x1b[H"
	cls     = "\x1b[2J"
	rev     = "\x1b[7m"

	// Arrow keys decode to private-use runes so they can never collide
	// with printable input typed into the target bar.
	keyUp    = rune(0xE000)
	keyDown  = rune(0xE001)
	keyRight = rune(0xE002)
	keyLeft  = rune(0xE003)
)

type line struct {
	lvl scanner.Level
	msg string
}

type TUI struct {
	mu       sync.Mutex
	lines    []line
	last     []string // rendered lines of output panel (for save)
	rendered bool

	sel      int
	panel    int // 0 modules, 1 output, 2 target
	target   string
	curPos   int
	scrl     int
	help     bool
	running  bool
	cancel   context.CancelFunc
	lastMod  string
	lastOpts modules.Options

	termW, termH int
}

// Run starts the interactive UI and blocks until quit.
func Run(ctx context.Context, initialTarget string) error {
	t := &TUI{panel: 0, target: initialTarget}
	if err := t.rawOn(); err != nil {
		return err
	}
	defer t.rawOff()
	t.render(true)

	in := make(chan rune, 64)
	errCh := make(chan error, 1)
	go t.reader(in, errCh)

	emit := func(l scanner.Level, msg string) { t.append(l, msg) }

	for {
		select {
		case <-ctx.Done():
			if t.cancel != nil {
				t.cancel()
			}
			t.statusLine("bye")
			return nil
		case err := <-errCh:
			t.statusLine("input error: " + err.Error())
			return err
		case r := <-in:
			if t.handleKey(r, emit) {
				return nil
			}
		}
	}
}

func (t *TUI) append(l scanner.Level, msg string) {
	t.mu.Lock()
	t.lines = append(t.lines, line{l, msg})
	if len(t.lines) > 5000 {
		t.lines = t.lines[len(t.lines)-5000:]
	}
	if t.panel != 1 {
		t.scrl = 0 // keep auto-scroll unless user is browsing output
	}
	t.mu.Unlock()
	t.render(false)
}

// handleKey returns true when the UI should quit.
func (t *TUI) handleKey(r rune, emit scanner.Emit) bool {
	if r == 0 {
		return false
	}
	if t.help {
		switch r {
		case 'h', 'q', 27, 'x':
			t.help = false
		}
		t.render(true)
		return false
	}
	switch r {
	case 'q':
		if !t.runningNow() {
			return true
		}
		if t.cancel != nil {
			t.cancel()
		}
	case 3: // Ctrl+C
		if t.runningNow() {
			if t.cancel != nil {
				t.cancel()
			}
		} else {
			return true
		}
	case 27: // Esc: cancel running scan
		if t.runningNow() && t.cancel != nil {
			t.cancel()
		}
	case '\t':
		t.setPanel((t.panel + 1) % 3)
		t.scrl = 0
		t.render(true)
	case '\n', '\r':
		t.runSelected(emit)
	case 's':
		t.saveReport()
	case 'h':
		t.help = true
		t.render(true)
	case 'r':
		if t.lastMod != "" && !t.runningNow() {
			t.runModule(t.lastMod, t.lastOpts, emit)
		}
	case 127, 8: // backspace
		if t.panel == 2 && t.curPos > 0 {
			t.target = t.target[:t.curPos-1] + t.target[t.curPos:]
			t.curPos--
			t.render(true)
		}
	case 0x15: // Ctrl+U clear input
		if t.panel == 2 {
			t.target = ""
			t.curPos = 0
			t.render(true)
		}
	case 1: // Ctrl+A home
		t.curPos = 0
		t.render(true)
	case 5: // Ctrl+E end
		t.curPos = len(t.target)
		t.render(true)
	case keyUp, keyDown, keyLeft, keyRight:
		switch t.panel {
		case 0:
			if r == keyUp {
				t.moveSel(-1)
			} else if r == keyDown {
				t.moveSel(1)
			}
		case 1:
			if r == keyUp {
				t.scroll(-1)
			} else if r == keyDown {
				t.scroll(1)
			}
		case 2:
			switch r {
			case keyLeft:
				if t.curPos > 0 {
					t.curPos--
					t.render(true)
				}
			case keyRight:
				if t.curPos < len(t.target) {
					t.curPos++
					t.render(true)
				}
			}
		}
	default:
		switch t.panel {
		case 0:
			switch r {
			case 'k':
				t.moveSel(-1)
			case 'j':
				t.moveSel(1)
			}
		case 1:
			switch r {
			case 'k':
				t.scroll(-1)
			case 'j':
				t.scroll(1)
			}
		case 2:
			if r >= 32 && r < 127 {
				t.target = t.target[:t.curPos] + string(r) + t.target[t.curPos:]
				t.curPos++
				t.render(true)
			}
		}
	}
	return false
}

func (t *TUI) runningNow() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.running
}

func (t *TUI) setPanel(p int) {
	t.mu.Lock()
	t.panel = p
	t.mu.Unlock()
}

func (t *TUI) moveSel(d int) {
	n := len(modules.Registry)
	t.sel = (t.sel + d + n) % n
	t.render(true)
}

func (t *TUI) scroll(d int) {
	t.mu.Lock()
	lines := len(t.lines)
	t.mu.Unlock()
	t.scrl += d
	max := lines - t.panelH()
	if max < 0 {
		max = 0
	}
	if t.scrl < 0 {
		t.scrl = 0
	}
	if t.scrl > max {
		t.scrl = max
	}
	t.render(true)
}

func (t *TUI) runSelected(emit scanner.Emit) {
	if t.runningNow() {
		t.statusLine("scan already running — press Esc to cancel")
		return
	}
	mod := modules.Registry[t.sel]
	target := strings.TrimSpace(t.target)
	if mod.NeedsTarget && target == "" {
		t.statusLine("enter a target first (e.g. http://127.0.0.1:8080)")
		t.panel = 2
		t.render(true)
		return
	}
	t.runModule(mod.Name, modules.Options{}, emit)
}

func (t *TUI) runModule(name string, opts modules.Options, emit scanner.Emit) {
	mod := modules.ByName(name)
	if mod == nil {
		return
	}
	target := strings.TrimSpace(t.target)
	if mod.NeedsTarget && target == "" {
		t.statusLine("no target set")
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.cancel = cancel
	t.running = true
	t.lastMod = name
	t.lastOpts = opts
	t.statusLine("running " + name + " ... (Esc to cancel)")
	t.append(scanner.LHl, "── hacklith: "+name+" ─────────────────────────────")

	go func() {
		err := mod.Run(ctx, target, opts, emit)
		t.mu.Lock()
		t.running = false
		t.cancel = nil
		t.mu.Unlock()
		if err != nil {
			emit(scanner.LCrit, "module error: "+err.Error())
		}
		t.statusLine("done: " + name + "   [s] save report  [r] rerun")
		t.render(true)
	}()
}

// ---- raw terminal helpers ----

func (t *TUI) rawOn() error {
	fd := int(os.Stdin.Fd())
	term, err := tcGet(fd)
	if err != nil {
		return err
	}
	raw := *term
	raw.Iflag &^= syscall.IGNBRK | syscall.BRKINT | syscall.PARMRK | syscall.ISTRIP |
		syscall.INLCR | syscall.IGNCR | syscall.ICRNL | syscall.IXON
	raw.Oflag &^= syscall.OPOST
	raw.Lflag &^= syscall.ECHO | syscall.ECHONL | syscall.ICANON | syscall.ISIG | syscall.IEXTEN
	raw.Cflag &^= syscall.CSIZE | syscall.PARENB
	raw.Cflag |= syscall.CS8
	raw.Cc[syscall.VMIN] = 1
	raw.Cc[syscall.VTIME] = 0
	if err := tcSet(fd, &raw); err != nil {
		return err
	}
	fmt.Fprint(os.Stdout, altOn+hideCur)
	return nil
}

func (t *TUI) rawOff() {
	fmt.Fprint(os.Stdout, showCur+altOff)
}

func tcGet(fd int) (*syscall.Termios, error) {
	var term syscall.Termios
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(syscall.TCGETS), uintptr(unsafe.Pointer(&term)))
	if errno != 0 {
		return nil, errno
	}
	return &term, nil
}

func tcSet(fd int, term *syscall.Termios) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(syscall.TCSETS), uintptr(unsafe.Pointer(term)))
	if errno != 0 {
		return errno
	}
	return nil
}

type winsize struct{ Row, Col, X, Y uint16 }

func termSize() (w, h int) {
	var ws winsize
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(os.Stdout.Fd()), uintptr(syscall.TIOCGWINSZ), uintptr(unsafe.Pointer(&ws)))
	if errno != 0 {
		return 80, 24
	}
	if ws.Col == 0 || ws.Row == 0 {
		return 80, 24
	}
	return int(ws.Col), int(ws.Row)
}

// reader decodes single bytes, arrow keys and escape sequences.
func (t *TUI) reader(ch chan<- rune, errCh chan<- error) {
	buf := make([]byte, 1)
	for {
		n, err := os.Stdin.Read(buf)
		if err != nil {
			errCh <- err
			return
		}
		if n == 0 {
			continue
		}
		b := buf[0]
		if b != 0x1b {
			ch <- rune(b)
			continue
		}
		// ESC: distinguish lone Esc from arrow keys via 50ms timeout.
		t.setReadTimeout(50)
		n, err = os.Stdin.Read(buf)
		t.setReadTimeout(0)
		if err != nil || n == 0 {
			ch <- 27 // lone Esc
			continue
		}
		if buf[0] == '[' {
			n, err = os.Stdin.Read(buf)
			if err != nil || n == 0 {
				ch <- 27
				continue
			}
			switch buf[0] {
			case 'A':
				ch <- keyUp
			case 'B':
				ch <- keyDown
			case 'C':
				ch <- keyRight
			case 'D':
				ch <- keyLeft
			default:
				ch <- 27
			}
			continue
		}
		ch <- 27 // unknown escape
	}
}

func (t *TUI) setReadTimeout(ms int) {
	fd := int(os.Stdin.Fd())
	term, err := tcGet(fd)
	if err != nil {
		return
	}
	if ms > 0 {
		term.Cc[syscall.VMIN] = 0
		term.Cc[syscall.VTIME] = uint8((ms + 99) / 100)
	} else {
		term.Cc[syscall.VMIN] = 1
		term.Cc[syscall.VTIME] = 0
	}
	_ = tcSet(fd, term)
}

// ---- rendering ----

func (t *TUI) render(force bool) {
	w, h := termSize()
	if w != t.termW || h != t.termH {
		t.termW, t.termH = w, h
		force = true
	}
	if !force {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	var sb strings.Builder
	sb.WriteString(home + cls)
	banner := bannerLines()
	// ANSI drop shadow: dark copy at +1,+1, bright copy on top.
	for i, bl := range banner {
		sb.WriteString(moveTo(2, 2+i))
		sb.WriteString(cli.CDim + bl + cli.CReset)
	}
	for i, bl := range banner {
		sb.WriteString(moveTo(1, 1+i))
		sb.WriteString(cli.CGreen + bl + cli.CReset)
	}
	top := len(banner) + 1

	// left panel: module list
	pw := 30
	if w < 80 {
		pw = 20
	}
	if pw > w/2 {
		pw = w / 2
	}
	ph := h - top - 3
	if ph < 3 {
		ph = 3
	}
	right := top
	sb.WriteString(moveTo(1, right))
	sb.WriteString(rev + pad("MODULES", pw) + cli.CReset)
	for i := 0; i < ph; i++ {
		mi := i
		row := right + 1 + i
		sb.WriteString(moveTo(1, row))
		if mi < len(modules.Registry) {
			m := modules.Registry[mi]
			name := m.Name
			if t.panel == 0 && mi == t.sel {
				sb.WriteString(rev + " " + padRight(name, pw-2) + " " + cli.CReset)
			} else {
				desc := m.Desc
				avail := pw - len(name) - 1
				if avail < 0 {
					avail = 0
				}
				sb.WriteString(cli.CReset + name + cli.CDim + " " + truncW(desc, avail) + cli.CReset)
			}
		} else {
			sb.WriteString(strings.Repeat(" ", pw))
		}
	}

	// right panel: output
	ow := w - pw - 1
	if ow < 10 {
		ow = 10
	}
	ox := pw + 1
	sb.WriteString(moveTo(ox, right))
	title := "OUTPUT"
	if t.running {
		title += "  (running...)"
	}
	sb.WriteString(rev + pad(title, ow) + cli.CReset)
	disp := t.outputLines(ph, ow)
	for i, d := range disp {
		sb.WriteString(moveTo(ox, right+1+i))
		sb.WriteString(padW(d, ow) + cli.CReset)
	}

	// bottom bar: target input / status / hints
	by := h
	sb.WriteString(moveTo(1, by))
	label := "TARGET"
	val := t.target
	if t.curPos > len(val) {
		t.curPos = len(val)
	}
	// render target field with reversed style when focused
	fieldW := w - 30
	if fieldW < 20 {
		fieldW = 20
	}
	field := padRight(val, fieldW)
	if t.panel == 2 {
		sb.WriteString(rev + label + " " + field + cli.CReset)
	} else {
		sb.WriteString(cli.CBold + label + cli.CReset + " " + field)
	}
	// status + hints on the same row, right-aligned
	status := "ready"
	if t.running {
		status = "RUNNING (Esc=cancel)"
	}
	hints := "[Tab]panels [Enter]run [s]save [h]help [q]quit"
	rightBar := " " + status + "  " + hints
	sb.WriteString(cli.CDim + rightBar + cli.CReset)

	// cursor placement
	cx := 8 + t.curPos
	if t.panel == 2 {
		sb.WriteString(moveTo(cx, h) + showCur)
	} else {
		sb.WriteString(moveTo(1, h) + hideCur)
	}

	if t.help {
		sb.WriteString(t.helpOverlay())
	}
	fmt.Fprint(os.Stdout, sb.String())
	t.rendered = true
}

func (t *TUI) outputLines(ph, ow int) []string {
	if len(t.lines) == 0 {
		return []string{cli.CDim + "no output yet — select a module and press Enter" + cli.CReset}
	}
	max := len(t.lines) - ph
	if max < 0 {
		max = 0
	}
	start := len(t.lines) - ph - t.scrl
	if start < 0 {
		start = 0
	}
	var out []string
	for i := start; i < len(t.lines) && len(out) < ph; i++ {
		l := t.lines[i]
		msg := wrapW(l.msg, ow)
		for j, m := range msg {
			if len(out) >= ph {
				break
			}
			colored := cli.Color(l.lvl) + cli.Tag(l.lvl) + " " + m + cli.CReset
			if j > 0 {
				colored = cli.CReset + "     " + m + cli.CReset
			}
			out = append(out, colored)
		}
	}
	if len(out) < ph {
		for len(out) < ph {
			out = append(out, "")
		}
	}
	return out
}

func (t *TUI) panelH() int {
	w, h := termSize()
	_ = w
	banner := 6
	return h - banner - 4
}

func (t *TUI) statusLine(s string) {
	t.append(scanner.LDim, s)
}

func (t *TUI) saveReport() {
	dir := "reports"
	_ = os.MkdirAll(dir, 0o755)
	fname := fmt.Sprintf("%s/hacklith_%s.txt", dir, time.Now().Format("20060102_150405"))
	f, err := os.Create(fname)
	if err != nil {
		t.statusLine("save failed: " + err.Error())
		return
	}
	defer f.Close()
	t.mu.Lock()
	for _, l := range t.lines {
		fmt.Fprintf(f, "%s %s\n", cli.Tag(l.lvl), l.msg)
	}
	t.mu.Unlock()
	t.statusLine("report saved: " + fname)
	t.render(true)
}

func (t *TUI) helpOverlay() string {
	lines := []string{
		" HACKQUAD KEYS",
		"",
		"  Tab         cycle panels (modules / output / target)",
		"  Up/Down     move selection or scroll output",
		"  Enter       run selected module",
		"  Esc         cancel running scan",
		"  r           rerun last module",
		"  s           save report to reports/",
		"  h           toggle this help",
		"  q / Ctrl+C  quit",
		"",
		"  Target may be a URL (http://host) or host:port.",
		"  Portscan spec: common | top | all | 80,443,8000-8100",
		"",
		"  Authorized use only.",
	}
	w, h := termSize()
	bw := 46
	startX := (w - bw) / 2
	startY := (h - len(lines)) / 2
	if startX < 1 {
		startX = 1
	}
	if startY < 1 {
		startY = 1
	}
	var sb strings.Builder
	for i, l := range lines {
		sb.WriteString(moveTo(startX, startY+i))
		sb.WriteString("\x1b[44m" + padW(l, bw) + cli.CReset)
	}
	return sb.String()
}

func moveTo(x, y int) string {
	return fmt.Sprintf("\x1b[%d;%dH", y, x)
}

func pad(s string, w int) string {
	if len(s) >= w {
		return s[:w]
	}
	return s + strings.Repeat(" ", w-len(s))
}

func padRight(s string, w int) string {
	return pad(s, w)
}

func padW(s string, w int) string {
	clean := stripANSI(s)
	if len(clean) >= w {
		return s
	}
	return s + strings.Repeat(" ", w-len(clean))
}

func stripANSI(s string) string {
	var sb strings.Builder
	in := false
	for _, r := range s {
		if r == '\x1b' {
			in = true
			continue
		}
		if in {
			if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' {
				in = false
			}
			continue
		}
		sb.WriteRune(r)
	}
	return sb.String()
}

func truncW(s string, w int) string {
	if w < 1 {
		return ""
	}
	if len(s) <= w {
		return s
	}
	if w <= 3 {
		return s[:w]
	}
	return s[:w-3] + "..."
}

func wrapW(s string, w int) []string {
	if w < 1 {
		w = 1
	}
	if len(s) <= w {
		return []string{s}
	}
	var out []string
	for len(s) > w {
		out = append(out, s[:w])
		s = s[w:]
	}
	out = append(out, s)
	return out
}

// bannerLines renders the 6-line HACKLITH block banner.
func bannerLines() []string {
	glyphs := map[rune][]string{
		'H': {"H   H", "H   H", "HHHHH", "H   H", "H   H", "H   H"},
		'A': {" AAA ", "A   A", "AAAAA", "A   A", "A   A", "A   A"},
		'C': {" CCCC", "C    ", "C    ", "C    ", "C    ", " CCCC"},
		'K': {"K  K ", "K K  ", "KK   ", "K K  ", "K  K ", "K  K "},
		'L': {"L    ", "L    ", "L    ", "L    ", "L    ", "LLLLL"},
		'I': {"  I  ", "  I  ", "  I  ", "  I  ", "  I  ", "  I  "},
		'T': {"TTTTT", "  T  ", "  T  ", "  T  ", "  T  ", "  T  "},
	}
	word := "HACKLITH"
	var rows [6]string
	for i := 0; i < 6; i++ {
		var sb strings.Builder
		for _, ch := range word {
			g, ok := glyphs[ch]
			if !ok {
				continue
			}
			sb.WriteString(g[i])
			sb.WriteString(" ")
		}
		rows[i] = sb.String()
	}
	return rows[:]
}



