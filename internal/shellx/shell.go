// Package shellx bridges hacklith to its bundled bash helper scripts
// (modules/shell/*.sh). Scripts run with stdout/stderr streamed line by
// line through the same Emit channel as Go modules, and are killed via
// their process group when a scan is cancelled.
package shellx

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/qingethical/hacklith/internal/scanner"
)

// ScriptDir returns the absolute path of the bundled shell scripts.
// HACKLITH_ROOT is exported by the hacklith.sh launcher.
func ScriptDir() string {
	if root := os.Getenv("HACKLITH_ROOT"); root != "" {
		return filepath.Join(root, "modules", "shell")
	}
	wd, err := os.Getwd()
	if err != nil {
		return "modules/shell"
	}
	return filepath.Join(wd, "modules", "shell")
}

// ListScripts returns the available .sh module names (without extension).
func ListScripts() []string {
	dir := ScriptDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sh") {
			continue
		}
		names = append(names, strings.TrimSuffix(e.Name(), ".sh"))
	}
	sort.Strings(names)
	return names
}

// RunScript executes a bundled script with $1=target, streaming output.
// The script is killed (process group) when ctx is cancelled.
func RunScript(ctx context.Context, name, target string, emit scanner.Emit) error {
	script := filepath.Join(ScriptDir(), name+".sh")
	if _, err := os.Stat(script); err != nil {
		return fmt.Errorf("script not found: %s", script)
	}
	emit(scanner.LHl, "shell: bash "+script+" "+target)

	cmd := exec.CommandContext(ctx, "bash", script, target)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	cmd.Env = append(os.Environ(), "HACKLITH_ROOT="+ScriptDir())

	if err := cmd.Start(); err != nil {
		return err
	}

	// Kill the whole process group on cancel so children die too.
	go func() {
		<-ctx.Done()
		if cmd.Process != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
	}()

	done := make(chan struct{})
	go func() {
		defer close(done)
		sc := bufio.NewScanner(stdout)
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for sc.Scan() {
			line := strings.TrimRight(sc.Text(), "\r")
			if line != "" {
				emit(scanner.LInfo, line)
			}
		}
		se := bufio.NewScanner(stderr)
		se.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for se.Scan() {
			line := strings.TrimRight(se.Text(), "\r")
			if line != "" {
				emit(scanner.LWarn, line)
			}
		}
	}()
	<-done
	err = cmd.Wait()
	if ctx.Err() != nil {
		emit(scanner.LWarn, "shell module cancelled")
		return nil
	}
	if err != nil {
		emit(scanner.LWarn, "script exited: "+err.Error())
	}
	emit(scanner.LInfo, "shell module finished in "+time.Now().Format("15:04:05"))
	return nil
}

// RunOnce runs a quick single command (used for whois-style one-shots).
func RunOnce(ctx context.Context, name string, args []string, emit scanner.Emit) error {
	emit(scanner.LHl, "shell: "+name+" "+strings.Join(args, " "))
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return nil
	}
	for _, line := range strings.Split(strings.TrimRight(string(out), "\n"), "\n") {
		if strings.TrimSpace(line) != "" {
			emit(scanner.LInfo, line)
		}
	}
	if err != nil {
		emit(scanner.LWarn, name+": "+err.Error())
	}
	return nil
}

