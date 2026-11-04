package main

import (
	"errors"
	"flag"
	"fmt"
	"strings"

	"github.com/Sh-Fang/vpnkit/internal/devid"
	"github.com/Sh-Fang/vpnkit/internal/fsutil"
	"github.com/Sh-Fang/vpnkit/internal/vpnerr"
)

func init() {
	register(command{"devid", "查看/固化设备特征码：devid show | devid pin [值]", cmdDevid})
	deviceID = func(a *app) (devid.HardID, error) {
		id, _, err := devid.Load(a.dir, devid.SystemSource{})
		return id, err
	}
	pinDeviceID = func(a *app, id devid.HardID) error {
		if cur, cached, err := devid.Load(a.dir, devid.SystemSource{}); err == nil && cached && cur.String() == id.String() {
			return nil // 已是同一个值，不重复写盘
		}
		if _, err := fsutil.EnsureDir(); err != nil {
			return err
		}
		return devid.Pin(a.dir, id)
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
		id, cached, err := devid.Load(a.dir, devid.SystemSource{})
		if err != nil {
			return err
		}
		src := "实时计算（未固化）"
		if cached {
			src = "已固化 " + devid.CachePath(a.dir)
		}
		a.printHardID(id, src)
		if !cached {
			a.printHardIDSource()
		}
		return nil
	case "pin":
		var value string
		switch len(rest) {
		case 1:
			// 不带值时固化本机当前算出的标识，这是 docs/06 §5 推荐的用法
			id, cached, err := devid.Load(a.dir, devid.SystemSource{})
			if err != nil {
				return err
			}
			if cached {
				fmt.Fprintf(a.stdout, "已固化，无需重复：%s\n", id)
				return nil
			}
			if err := a.writeHardID(id); err != nil {
				return err
			}
			a.printHardID(id, "已固化 "+devid.CachePath(a.dir))
			return nil
		case 2:
			value = strings.TrimSpace(rest[1])
		default:
			return fmt.Errorf("%w: devid pin 至多一个参数", vpnerr.ErrUsage)
		}
		id, err := a.resolveHardID(value)
		if err != nil {
			return fmt.Errorf("%w: %w", vpnerr.ErrUsage, err)
		}
		if err := a.writeHardID(id); err != nil {
			return err
		}
		a.printHardID(id, "已固化 "+devid.CachePath(a.dir))
		fmt.Fprintln(a.stdout, "仅限本机使用，不得复制到其他机器（docs/06 §5）")
		return nil
	}
	return fmt.Errorf("%w: 未知子命令 devid %s", vpnerr.ErrUsage, rest[0])
}

// resolveHardID 接受完整三段值，或只有第一段时用本机现值补齐另两段。
func (a *app) resolveHardID(value string) (devid.HardID, error) {
	id, err := devid.Parse(value)
	if err != nil {
		return devid.HardID{}, err
	}
	if id.MAC != "" && id.HostName != "" {
		return id, nil
	}
	local := devid.Inspect(devid.SystemSource{})
	if id.MAC == "" {
		id.MAC = local.MAC
	}
	if id.HostName == "" {
		id.HostName = devid.HostNameField(local.HostName)
	}
	if id.MAC == "" {
		return devid.HardID{}, errors.New("补齐 MAC 段失败：本机没有带硬件的网卡")
	}
	return id, nil
}

func (a *app) writeHardID(id devid.HardID) error {
	if _, err := fsutil.EnsureDir(); err != nil {
		return err
	}
	return devid.Pin(a.dir, id)
}

func (a *app) printHardID(id devid.HardID, source string) {
	fmt.Fprintf(a.stdout, "hid      = %s\n", id.HID)
	fmt.Fprintf(a.stdout, "mac      = %s\n", id.MAC)
	fmt.Fprintf(a.stdout, "hostname = %s（base64）\n", id.HostName)
	fmt.Fprintf(a.stdout, "来源     = %s\n", source)
}

// printHardIDSource 打印取数细节：磁盘这路要 root，取不到就得说清楚。
func (a *app) printHardIDSource() {
	p := devid.Inspect(devid.SystemSource{})
	switch {
	case p.DiskOK:
		fmt.Fprintf(a.stdout, "磁盘序列号 = %q（已纳入）\n", p.DiskSerial)
	case p.DiskErr != nil:
		fmt.Fprintf(a.stdout, "磁盘序列号 = 取不到（%v）\n", p.DiskErr)
		fmt.Fprintln(a.stdout, "            只有 MAC 参与计算，与官方客户端的结果不同；用 root 跑 devid show 才是完整值")
	default:
		fmt.Fprintln(a.stdout, "磁盘序列号 = 无")
	}
	if p.MAC == "" {
		fmt.Fprintln(a.stdout, "网卡 MAC  = 无")
	} else {
		fmt.Fprintf(a.stdout, "网卡 MAC  = %s\n", p.MAC)
	}
}
