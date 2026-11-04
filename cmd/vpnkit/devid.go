package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/Sh-Fang/vpnkit/internal/devid"
	"github.com/Sh-Fang/vpnkit/internal/fsutil"
	"github.com/Sh-Fang/vpnkit/internal/vpnerr"
)

func init() {
	register(command{"devid", "查看/固化设备标识：devid show | devid pin [值]", cmdDevid})
	deviceID = func(a *app) (string, error) {
		id, _, err := devid.Get(a.dir, devid.SystemSource{})
		return id, err
	}
	pinDeviceID = func(a *app, id string) error {
		if cur, cached, err := devid.Get(a.dir, devid.SystemSource{}); err == nil && cached && cur == id {
			return nil // 已是同一个值，不重复写盘
		}
		if _, err := fsutil.EnsureDir(); err != nil {
			return err
		}
		return devid.Pin(a.dir, id)
	}
	hidExtras = func(a *app) (string, string) {
		mac, _ := devid.PrimaryMAC(devid.SystemSource{})
		host, _ := os.Hostname()
		return mac, host
	}
}

func cmdDevid(a *app, args []string) error {
	fs := flag.NewFlagSet("devid", flag.ContinueOnError)
	if err := a.parse(fs, args); err != nil {
		return err
	}
	if err := a.initLog(); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) == 0 {
		return fmt.Errorf("%w: 用法 vpnkit devid show | vpnkit devid pin [值]", vpnerr.ErrUsage)
	}
	switch rest[0] {
	case "show":
		if len(rest) != 1 {
			return fmt.Errorf("%w: devid show 不接受参数", vpnerr.ErrUsage)
		}
		id, cached, err := devid.Get(a.dir, devid.SystemSource{})
		if err != nil {
			return err
		}
		src := "实时计算（未固化）"
		if cached {
			src = "已固化 " + devid.CachePath(a.dir)
		}
		fmt.Fprintf(a.stdout, "%s\t%s\n", id, src)
		return nil
	case "pin":
		var value string
		switch len(rest) {
		case 1:
			// 不带值时固化本机当前算出的标识，这是 docs/06 §5 推荐的用法
			id, cached, err := devid.Get(a.dir, devid.SystemSource{})
			if err != nil {
				return err
			}
			if cached {
				fmt.Fprintf(a.stdout, "已固化，无需重复：%s\n", id)
				return nil
			}
			value = id
		case 2:
			value = strings.TrimSpace(rest[1])
		default:
			return fmt.Errorf("%w: devid pin 至多一个参数", vpnerr.ErrUsage)
		}
		if _, err := fsutil.EnsureDir(); err != nil {
			return err
		}
		if err := devid.Pin(a.dir, value); err != nil {
			return fmt.Errorf("%w: %w", vpnerr.ErrUsage, err)
		}
		fmt.Fprintf(a.stdout, "已固化设备标识到 %s\n仅限本机使用，不得复制到其他机器（docs/06 §5）\n", devid.CachePath(a.dir))
		return nil
	}
	return fmt.Errorf("%w: 未知子命令 devid %s", vpnerr.ErrUsage, rest[0])
}
