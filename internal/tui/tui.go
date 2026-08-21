package tui

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/lipgloss"
	"github.com/qingethical/hacklith/internal/cli"
	"github.com/qingethical/hacklith/internal/modules"
	"github.com/qingethical/hacklith/internal/scanner"
	tea "github.com/charmbracelet/bubbletea"
)

var (
	bannerLines []string
	bannerOnce  sync.Once
)

func getBanner() []string {
	bannerOnce.Do(func() {
		paths := []string{}
		if root := os.Getenv("HACKLITH_ROOT"); root != "" {
			paths = append(paths, filepath.Join(root, "internal", "assets", "banner.txt"))
		}
		if exe, err := os.Executable(); err == nil {
			paths = append(paths, filepath.Join(filepath.Dir(exe), "..", "internal", "assets", "banner.txt"))
			paths = append(paths, filepath.Join(filepath.Dir(exe), "internal", "assets", "banner.txt"))
		}
		paths = append(paths, "internal/assets/banner.txt")
		paths = append(paths, "banner.txt")

		for _, p := range paths {
			if data, err := os.ReadFile(p); err == nil {
				bannerLines = strings.Split(string(data), "\n")
				break
			}
		}
		if len(bannerLines) == 0 {
			bannerLines = []string{"HACKLITH"}
		}
	})
	return bannerLines
}

var (
	moduleStyle   = lipgloss.NewStyle().PaddingLeft(1)
	selectedStyle = lipgloss.NewStyle().PaddingLeft(1).Background(lipgloss.Color("62")).Foreground(lipgloss.Color("230"))
	targetStyle   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("86"))
	statusStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("241")).PaddingLeft(1)
	bannerStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("46")).Bold(true)
)

type line struct {
	lvl scanner.Level
	msg string
}

type moduleItem struct {
	name string
	desc string
}

type model struct {
	modules     []moduleItem
	selected    int
	panel       int
	target      string
	targetInput textinput.Model
	output      []line
	scroll      int
	help        bool
	running     bool
	status      string
	width       int
	height      int
	banner      []string

	cancel   context.CancelFunc
	lastMod  string
	lastOpts modules.Options
	program  *tea.Program
}

type doneMsg struct{}

type outputMsg struct {
	lvl scanner.Level
	msg string
}

type statusMsg string

type errMsg struct {
	err error
}

func initialModel(initialTarget string) model {
	ti := textinput.New()
	ti.Placeholder = "http://target or host:port"
	ti.Width = 60
	ti.SetValue(initialTarget)
	ti.Focus()

	var mods []moduleItem
	for _, m := range modules.Registry {
		mods = append(mods, moduleItem{name: m.Name, desc: m.Desc})
	}

	return model{
		modules:     mods,
		panel:       0,
		target:      initialTarget,
		targetInput: ti,
		banner:      getBanner(),
		status:      "ready",
		width:       80,
		height:      24,
	}
}

func (m *model) Init() tea.Cmd {
	return textinput.Blink
}

func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.targetInput.Width = msg.Width - 20
		if m.targetInput.Width < 20 {
			m.targetInput.Width = 20
		}
		return m, nil

	case tea.KeyMsg:
		// Let textinput handle keys when focused
		if m.panel == 2 && m.targetInput.Focused() {
			var cmd tea.Cmd
			m.targetInput, cmd = m.targetInput.Update(msg)
			m.target = m.targetInput.Value()
			if msg.String() == "enter" {
				m.runSelected()
				return m, cmd
			}
			if msg.String() == "tab" {
				m.panel = (m.panel + 1) % 3
				if m.panel == 2 {
					m.targetInput.Focus()
				} else {
					m.targetInput.Blur()
				}
				m.scroll = 0
				return m, cmd
			}
			return m, cmd
		}
		return m.handleKey(msg), nil

	case outputMsg:
		m.output = append(m.output, line{lvl: msg.lvl, msg: msg.msg})
		if len(m.output) > 5000 {
			m.output = m.output[len(m.output)-5000:]
		}
		if m.panel != 1 {
			m.scroll = 0
		}
		return m, nil

	case statusMsg:
		m.status = string(msg)
		return m, nil

	case errMsg:
		m.status = "error: " + msg.err.Error()
		m.running = false
		m.cancel = nil
		return m, nil

	case doneMsg:
		m.running = false
		m.cancel = nil
		return m, nil
	}

	return m, nil
}

func (m *model) handleKey(msg tea.KeyMsg) tea.Model {
	if m.help {
		if msg.String() == "h" || msg.String() == "q" || msg.String() == "esc" {
			m.help = false
			return m
		}
		return m
	}

	switch msg.String() {
	case "q":
		if !m.running {
			return m
		}
		if m.cancel != nil {
			m.cancel()
		}
		m.status = "cancelling..."
	case "ctrl+c":
		if m.running {
			if m.cancel != nil {
				m.cancel()
			}
			m.status = "cancelling..."
		} else {
			return m
		}
	case "esc":
		if m.running && m.cancel != nil {
			m.cancel()
			m.status = "cancelling..."
		}
	case "tab":
		m.panel = (m.panel + 1) % 3
		if m.panel == 2 {
			m.targetInput.Focus()
		} else {
			m.targetInput.Blur()
		}
		m.scroll = 0
	case "enter":
		if m.panel == 2 {
			m.runSelected()
		} else {
			m.runSelected()
		}
	case "s":
		m.saveReport()
	case "h":
		m.help = true
	case "r":
		if m.lastMod != "" && !m.running {
			m.runModule(m.lastMod, m.lastOpts)
		}
	case "k":
		if m.panel == 0 && m.selected > 0 {
			m.selected--
		} else if m.panel == 1 {
			m.scroll--
		}
	case "j":
		if m.panel == 0 && m.selected < len(m.modules)-1 {
			m.selected++
		} else if m.panel == 1 {
			m.scroll++
		}
	case "up":
		if m.panel == 0 {
			if m.selected > 0 {
				m.selected--
			}
		} else if m.panel == 1 {
			m.scroll--
		}
	case "down":
		if m.panel == 0 {
			if m.selected < len(m.modules)-1 {
				m.selected++
			}
		} else if m.panel == 1 {
			m.scroll++
		}
	case "ctrl+u":
		if m.panel == 2 {
			m.targetInput.SetValue("")
			m.target = ""
		}
	case "ctrl+a":
		if m.panel == 2 {
			m.targetInput.CursorStart()
		}
	case "ctrl+e":
		if m.panel == 2 {
			m.targetInput.CursorEnd()
		}
	}

	if m.scroll < 0 {
		m.scroll = 0
	}
	m.target = m.targetInput.Value()
	return m
}

func (m *model) runSelected() {
	if m.running {
		m.status = "scan already running — press Esc to cancel"
		return
	}
	if m.selected < 0 || m.selected >= len(m.modules) {
		return
	}
	mod := m.modules[m.selected]
	target := strings.TrimSpace(m.target)
	modObj := modules.ByName(mod.name)
	if modObj == nil {
		return
	}
	if modObj.NeedsTarget && target == "" {
		m.status = "enter a target first"
		m.panel = 2
		return
	}
	m.runModule(mod.name, modules.Options{})
}

func (m *model) runModule(name string, opts modules.Options) {
	mod := modules.ByName(name)
	if mod == nil {
		return
	}
	target := strings.TrimSpace(m.target)
	if mod.NeedsTarget && target == "" {
		m.status = "no target set"
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel
	m.running = true
	m.lastMod = name
	m.lastOpts = opts
	m.status = "running " + name + " ... (Esc to cancel)"
	m.output = append(m.output, line{lvl: scanner.LHl, msg: "── " + name + " ─────────────────────────────"})

	go func() {
		start := time.Now()
		emit := func(l scanner.Level, msg string) {
			if m.program != nil {
				m.program.Send(outputMsg{lvl: l, msg: msg})
			}
		}
		err := mod.Run(ctx, target, opts, emit)
		if err != nil {
			emit(scanner.LCrit, "module error: "+err.Error())
		}
		elapsed := time.Since(start).Round(time.Millisecond)
		if m.program != nil {
			m.program.Send(statusMsg("done: " + name + "   [s] save report  [r] rerun"))
			m.program.Send(outputMsg{lvl: scanner.LDim, msg: "finished in " + elapsed.String()})
			m.program.Send(doneMsg{})
		}
	}()
}

func (m *model) saveReport() {
	dir := "reports"
	_ = os.MkdirAll(dir, 0o755)
	fname := fmt.Sprintf("%s/hacklith_%s.txt", dir, time.Now().Format("20060102_150405"))
	f, err := os.Create(fname)
	if err != nil {
		m.status = "save failed: " + err.Error()
		return
	}
	defer f.Close()
	for _, l := range m.output {
		fmt.Fprintf(f, "%s %s\n", cli.Tag(l.lvl), l.msg)
	}
	m.status = "report saved: " + fname
}

func (m *model) View() string {
	w := m.width
	h := m.height
	if w < 1 {
		w = 80
	}
	if h < 1 {
		h = 24
	}

	var sb strings.Builder

	banner := getBanner()
	for i, bl := range banner {
		if i < h-3 {
			sb.WriteString(bannerStyle.Render(bl) + "\n")
		}
	}

	top := len(banner) + 1
	if top > h-3 {
		top = h - 3
	}

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

	var modList strings.Builder
	modList.WriteString(lipgloss.NewStyle().Reverse(true).Render(" MODULES ") + "\n")
	for i := 0; i < ph; i++ {
		if i >= len(m.modules) {
			modList.WriteString(strings.Repeat(" ", pw) + "\n")
			continue
		}
		mod := m.modules[i]
		if m.panel == 0 && i == m.selected {
			modList.WriteString(selectedStyle.Render("> " + mod.name + " " + truncate(mod.desc, pw-len(mod.name)-3)) + "\n")
		} else {
			modList.WriteString(moduleStyle.Render("  " + mod.name + " " + truncate(mod.desc, pw-len(mod.name)-3)) + "\n")
		}
	}

	ow := w - pw - 1
	if ow < 10 {
		ow = 10
	}
	var outList strings.Builder
	outList.WriteString(lipgloss.NewStyle().Reverse(true).Render(" OUTPUT ") + "\n")
	lines := m.output
	if len(lines) == 0 {
		outList.WriteString(cli.CDim + "no output yet — select a module and press Enter" + cli.CReset + "\n")
	} else {
		start := len(lines) - ph - m.scroll
		if start < 0 {
			start = 0
		}
		for i := start; i < len(lines) && i-start < ph; i++ {
			l := lines[i]
			outList.WriteString(cli.Color(l.lvl) + cli.Tag(l.lvl) + " " + truncate(l.msg, ow-6) + cli.CReset + "\n")
		}
		for i := len(lines) - start; i < ph && i >= 0; i++ {
			outList.WriteString("\n")
		}
	}

	left := modList.String()
	right := outList.String()
	combined := lipgloss.JoinHorizontal(lipgloss.Top, left, right)
	sb.WriteString(combined)

	sb.WriteString("\n")
	fieldW := w - 30
	if fieldW < 20 {
		fieldW = 20
	}
	targetVal := m.target
	if len(targetVal) > fieldW {
		targetVal = targetVal[:fieldW-3] + "..."
	}
	field := targetVal + strings.Repeat(" ", fieldW-len(targetVal))
	if m.panel == 2 {
		sb.WriteString(targetStyle.Render("TARGET ") + lipgloss.NewStyle().Reverse(true).Render(field))
	} else {
		sb.WriteString(targetStyle.Render("TARGET ") + field)
	}

	status := m.status
	hints := "[Tab]panels [Enter]run [s]save [h]help [q]quit"
	sb.WriteString(" " + statusStyle.Render(" "+status+"  "+hints))

	if m.help {
		sb.WriteString("\n" + m.helpOverlay())
	}

	return sb.String()
}

func (m *model) helpOverlay() string {
	lines := []string{
		" HACKLITH KEYS",
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
	w := m.width
	if w < 1 {
		w = 80
	}
	bw := 46
	startX := (w - bw) / 2
	if startX < 1 {
		startX = 1
	}
	var sb strings.Builder
	for _, l := range lines {
		sb.WriteString(strings.Repeat(" ", startX) + lipgloss.NewStyle().Background(lipgloss.Color("4")).Render(truncate(l, bw)) + "\n")
	}
	return sb.String()
}

func truncate(s string, n int) string {
	if n < 1 {
		return ""
	}
	if len(s) <= n {
		return s
	}
	if n <= 3 {
		return s[:n]
	}
	return s[:n-3] + "..."
}

func Run(ctx context.Context, initialTarget string) error {
	m := initialModel(initialTarget)
	p := tea.NewProgram(&m, tea.WithAltScreen())
	m.program = p

	go func() {
		<-ctx.Done()
		if m.cancel != nil {
			m.cancel()
		}
		p.Quit()
	}()

	if _, err := p.Run(); err != nil {
		return err
	}
	return nil
}
