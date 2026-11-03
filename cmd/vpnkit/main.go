// vpnkit：兼容某商用 SSL VPN 网关的命令行客户端，只把内网流量送进隧道（docs/00）。
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Sh-Fang/vpnkit/internal/config"
	"github.com/Sh-Fang/vpnkit/internal/fsutil"
	"github.com/Sh-Fang/vpnkit/internal/logx"
	"github.com/Sh-Fang/vpnkit/internal/vpnerr"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// globals 是 docs/00 §4.2 的全局参数，每个子命令都接受。
type globals struct {
	config  string
	verbose bool
	trace   bool
	json    bool
	timeout time.Duration
}

func (g *globals) register(fs *flag.FlagSet) {
	fs.StringVar(&g.config, "config", "", "配置文件路径（默认 ~/.config/vpnkit/config.toml）")
	fs.BoolVar(&g.verbose, "verbose", false, "调试日志（debug 级），同时写日志文件")
	fs.BoolVar(&g.trace, "trace", false, "在 debug 之上输出每个 IP 包的头部摘要（不含负载）")
	fs.BoolVar(&g.json, "json", false, "机器可读输出（status/doctor）")
	fs.DurationVar(&g.timeout, "timeout", 30*time.Second, "单次网络操作超时")
}

// app 是一次命令执行的上下文。
type app struct {
	g      globals
	stdout io.Writer
	stderr io.Writer
	cfg    *config.Config
	log    *slog.Logger
	dir    string
	close  func()
}

type command struct {
	name    string
	summary string
	run     func(a *app, args []string) error
}

var commands []command

func register(c command) { commands = append(commands, c) }

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	args = hoistCommand(args)
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		usage(stderr)
		if len(args) == 0 {
			return 2
		}
		return 0
	}
	if args[0] == "--version" || args[0] == "-version" || args[0] == "version" {
		fmt.Fprintf(stdout, "vpnkit %s\ncommit %s\nbuilt %s\n", version, commit, date)
		return 0
	}
	for _, c := range commands {
		if c.name == args[0] {
			a := &app{stdout: stdout, stderr: stderr, close: func() {}}
			err := c.run(a, args[1:])
			a.close()
			if err != nil {
				if errors.Is(err, flag.ErrHelp) {
					return 0
				}
				fmt.Fprintln(stderr, "错误:", err)
				return vpnerr.ExitCode(err)
			}
			return 0
		}
	}
	fmt.Fprintf(stderr, "未知命令 %q\n\n", args[0])
	usage(stderr)
	return 2
}

// hoistCommand 允许把全局参数写在子命令前面：vpnkit --verbose up → up --verbose。
func hoistCommand(args []string) []string {
	valueFlags := map[string]bool{"config": true, "timeout": true}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") {
			if i == 0 {
				return args
			}
			out := append([]string{a}, args[:i]...)
			return append(out, args[i+1:]...)
		}
		name := strings.TrimLeft(a, "-")
		if valueFlags[name] && !strings.Contains(name, "=") {
			i++
		}
	}
	return args
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "用法: vpnkit <命令> [参数]")
	fmt.Fprintln(w)
	sorted := append([]command(nil), commands...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].name < sorted[j].name })
	for _, c := range sorted {
		fmt.Fprintf(w, "  %-8s %s\n", c.name, c.summary)
	}
	fmt.Fprintln(w, "\n全局参数: --config --verbose --trace --json --timeout；vpnkit --version 查看版本")
}

// parse 解析子命令参数，加载配置并初始化日志。
func (a *app) parse(fs *flag.FlagSet, args []string) error {
	a.g.register(fs)
	fs.SetOutput(a.stderr)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return fmt.Errorf("%w: %w", vpnerr.ErrUsage, err)
	}
	if fs.NArg() > 0 && fs.Name() != "devid" {
		return fmt.Errorf("%w: 多余的参数 %v", vpnerr.ErrUsage, fs.Args())
	}
	cfg, err := config.Load(a.g.config)
	if err != nil {
		return err
	}
	a.cfg = cfg
	dir, err := fsutil.Dir()
	if err != nil {
		return err
	}
	a.dir = dir
	return nil
}

// initLog 在命令行覆盖完配置后初始化日志。
func (a *app) initLog() error {
	level, err := logx.ParseLevel(a.cfg.Log.Level)
	if err != nil {
		return fmt.Errorf("%w: %w", vpnerr.ErrUsage, err)
	}
	opts := logx.Options{Level: level, Format: a.cfg.Log.Format, Stderr: a.stderr, FileKeep: a.cfg.Log.FileKeep}
	if a.g.verbose && level > slog.LevelDebug {
		opts.Level = slog.LevelDebug
	}
	if a.g.trace {
		opts.Level = logx.LevelTrace
	}
	if a.g.verbose || a.g.trace {
		if _, err := fsutil.EnsureDir(); err == nil {
			opts.FileDir = filepath.Join(a.dir, "logs")
		}
	}
	l, closeFn, err := logx.Setup(opts)
	if err != nil {
		return err
	}
	a.log, a.close = l, closeFn
	for _, w := range a.cfg.Warnings {
		a.log.Warn(w)
	}
	return nil
}
