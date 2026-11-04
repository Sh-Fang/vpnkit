// Package config 实现 docs/09 的配置模型：默认值 < 配置文件 < 环境变量 < 命令行。
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/Sh-Fang/vpnkit/internal/fsutil"
	"github.com/Sh-Fang/vpnkit/internal/logx"
	"github.com/Sh-Fang/vpnkit/internal/vpnerr"
)

// Duration 让 "10s" 这类字符串直接解进配置。
type Duration struct{ time.Duration }

type Server struct {
	Host string `toml:"host"`
	Port int    `toml:"port"`
	Auth string `toml:"auth"`
	// 网关多为自签证书。默认仍校验证书；用 ca_file 信任指定 CA，
	// 或显式 insecure=true 跳过（会打 warn）。这类网关的出厂证书多为自签且不带 SAN，ca_file 也校验不过，
	// 此时用 cert_sha256 只认这一张证书。
	Insecure   bool   `toml:"insecure"`
	CAFile     string `toml:"ca_file"`
	CertSHA256 string `toml:"cert_sha256"`
}

type Auth struct {
	User         string `toml:"user"`
	MitmField    string `toml:"mitm_field"`
	SendRandCode bool   `toml:"send_rand_code"`
	SendDeviceID string `toml:"send_device_id"` // auto | always | never
	// 设备标识在登录表单中的字段名。原始资料未给出，属假设点 device_id_field。
	DeviceIDField string `toml:"device_id_field"`
	// 网关要求 auth/hid 二次认证（特征码）时的提交参数。默认值取自官方客户端的实际请求
	// （docs/02 §4、docs/06 §6），一般不需要改。
	RegisterDevice bool   `toml:"register_device"` // true 时自动提交本机特征码
	HIDEndpoint    string `toml:"hid_endpoint"`    // 认证这步，默认 /por/login_hid.csp
	HIDQuery       string `toml:"hid_query"`       // 上面这个端点固定的查询串
	HIDField       string `toml:"hid_field"`       // 特征码表单字段名，默认 hid
	HIDLanguage    string `toml:"hid_language"`    // 绑定申请里的 language 参数，默认 zh_CN
	// 提交设备绑定申请（进管理员审批队列）的端点，参数走查询串。
	SubmitHIDEndpoint string `toml:"submithid_endpoint"` // 默认 /por/submithid.csp
}

type Tunnel struct {
	MTU               int      `toml:"mtu"`
	Transport         string   `toml:"transport"`
	HeartbeatInterval Duration `toml:"heartbeat_interval"`
	HeartbeatTimeout  Duration `toml:"heartbeat_timeout"`
	ConnectTimeout    Duration `toml:"connect_timeout"`
	HandshakeTimeout  Duration `toml:"handshake_timeout"`
	ValidWait         Duration `toml:"valid_wait"`
	CtrlConnType      int      `toml:"ctrl_conn_type"`
	TokenEncoding     string   `toml:"token_encoding"`
	DataOpcode        int      `toml:"data_opcode"`
	RC4KeyHex         string   `toml:"rc4_key_hex"`
	// 数据通道建连的 conn_type（docs/03 §4.3 允许 6/7 上行、5/8 下行），假设点 data_conn。
	DataConnUp   int `toml:"data_conn_up"`
	DataConnDown int `toml:"data_conn_down"`
}

type Split struct {
	ExtraRoutes []string `toml:"extra_routes"`
	Bypass      []string `toml:"bypass"`
}

type DNS struct {
	Suffixes []string `toml:"suffixes"`
	Servers  []string `toml:"servers"`
}

type Log struct {
	Level    string `toml:"level"`
	Format   string `toml:"format"`
	FileKeep int    `toml:"file_keep"`
}

type Config struct {
	Server Server `toml:"server"`
	Auth   Auth   `toml:"auth"`
	Tunnel Tunnel `toml:"tunnel"`
	Split  Split  `toml:"split"`
	DNS    DNS    `toml:"dns"`
	Log    Log    `toml:"log"`

	// Path 是实际加载的配置文件路径（可能不存在）。
	Path string `toml:"-"`
	// Warnings 收集未知键等非致命问题，由调用方决定如何输出。
	Warnings []string `toml:"-"`
}

// Default 返回 docs/09 §1 的内置默认值。
func Default() *Config {
	return &Config{
		Server: Server{Port: 443, Auth: "password"},
		Auth: Auth{
			MitmField:         "mitm_result",
			SendDeviceID:      "auto",
			DeviceIDField:     "devid",
			HIDEndpoint:       "/por/login_hid.csp",
			HIDQuery:          "type=cs&language=zh_CN&encrypt=1",
			HIDField:          "hid",
			HIDLanguage:       "zh_CN",
			SubmitHIDEndpoint: "/por/submithid.csp",
		},
		Tunnel: Tunnel{
			MTU:               1400,
			Transport:         "tcp",
			HeartbeatInterval: Duration{10 * time.Second},
			HeartbeatTimeout:  Duration{30 * time.Second},
			ConnectTimeout:    Duration{10 * time.Second},
			HandshakeTimeout:  Duration{15 * time.Second},
			ValidWait:         Duration{10 * time.Second},
			CtrlConnType:      1,
			TokenEncoding:     "ascii",
			DataOpcode:        0,
			DataConnUp:        6,
			DataConnDown:      5,
		},
		Log: Log{Level: "info", Format: "text", FileKeep: 10},
	}
}

// DefaultPath 返回默认配置文件路径。
func DefaultPath() (string, error) {
	d, err := fsutil.Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "config.toml"), nil
}

// Load 依次叠加默认值、配置文件、环境变量。path 为空时用 VPNKIT_CONFIG 或默认路径；
// 默认路径下文件不存在不算错误，显式指定的路径不存在则报错。
func Load(path string) (*Config, error) {
	c := Default()
	explicit := path != ""
	if !explicit {
		if p := os.Getenv("VPNKIT_CONFIG"); p != "" {
			path, explicit = p, true
		} else {
			p, err := DefaultPath()
			if err != nil {
				return nil, err
			}
			path = p
		}
	}
	c.Path = path
	b, err := os.ReadFile(path)
	switch {
	case err == nil:
		if err := c.apply(string(b)); err != nil {
			return nil, fmt.Errorf("%w: 配置文件 %s: %w", vpnerr.ErrUsage, path, err)
		}
		if ok, err := fsutil.Private(path); err == nil && !ok {
			c.Warnings = append(c.Warnings, fmt.Sprintf("配置文件 %s 其他用户可访问，建议收紧为仅本人可读写（0600）", path))
		}
	case errors.Is(err, os.ErrNotExist) && !explicit:
	default:
		return nil, fmt.Errorf("%w: 读取配置: %w", vpnerr.ErrUsage, err)
	}
	c.applyEnv()
	return c, nil
}

func (c *Config) applyEnv() {
	if v := os.Getenv("VPNKIT_SERVER"); v != "" {
		c.Server.Host = v
	}
	if v := os.Getenv("VPNKIT_USER"); v != "" {
		c.Auth.User = v
	}
	if v := os.Getenv("VPNKIT_LOG_LEVEL"); v != "" {
		c.Log.Level = v
	}
}

func (c *Config) apply(src string) error {
	tree, err := parseTOML(src)
	if err != nil {
		return err
	}
	root := reflect.ValueOf(c).Elem()
	for section, kv := range tree {
		if section == "" {
			for k := range kv {
				c.Warnings = append(c.Warnings, "忽略顶层键 "+k)
			}
			continue
		}
		sv, ok := fieldByTag(root, section)
		if !ok || sv.Kind() != reflect.Struct {
			c.Warnings = append(c.Warnings, "忽略未知段 ["+section+"]")
			continue
		}
		for k, raw := range kv {
			fv, ok := fieldByTag(sv, k)
			if !ok {
				c.Warnings = append(c.Warnings, fmt.Sprintf("忽略未知键 %s.%s", section, k))
				continue
			}
			if err := assign(fv, raw); err != nil {
				return fmt.Errorf("%s.%s: %w", section, k, err)
			}
		}
	}
	return nil
}

func fieldByTag(v reflect.Value, tag string) (reflect.Value, bool) {
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		if t.Field(i).Tag.Get("toml") == tag {
			return v.Field(i), true
		}
	}
	return reflect.Value{}, false
}

var durationType = reflect.TypeOf(Duration{})

func assign(fv reflect.Value, raw any) error {
	if fv.Type() == durationType {
		s, ok := raw.(string)
		if !ok {
			return fmt.Errorf("需要时长字符串，如 \"10s\"")
		}
		d, err := time.ParseDuration(s)
		if err != nil {
			return err
		}
		fv.Set(reflect.ValueOf(Duration{d}))
		return nil
	}
	switch fv.Kind() {
	case reflect.String:
		s, ok := raw.(string)
		if !ok {
			return fmt.Errorf("需要字符串")
		}
		fv.SetString(s)
	case reflect.Int:
		n, ok := raw.(int64)
		if !ok {
			return fmt.Errorf("需要整数")
		}
		fv.SetInt(n)
	case reflect.Bool:
		b, ok := raw.(bool)
		if !ok {
			return fmt.Errorf("需要 true/false")
		}
		fv.SetBool(b)
	case reflect.Slice:
		arr, ok := raw.([]any)
		if !ok {
			return fmt.Errorf("需要数组")
		}
		out := make([]string, 0, len(arr))
		for _, a := range arr {
			s, ok := a.(string)
			if !ok {
				return fmt.Errorf("数组元素需要字符串")
			}
			out = append(out, s)
		}
		fv.Set(reflect.ValueOf(out))
	default:
		return fmt.Errorf("内部错误: 不支持的字段类型 %v", fv.Kind())
	}
	return nil
}

// Validate 执行 docs/09 §5 中不依赖运行时信息的检查。
// needServer 为 false 时（如 devid 子命令）不要求 server.host。
func (c *Config) Validate(needServer bool) error {
	bad := func(format string, a ...any) error {
		return fmt.Errorf("%w: %s", vpnerr.ErrUsage, fmt.Sprintf(format, a...))
	}
	if needServer && strings.TrimSpace(c.Server.Host) == "" {
		return bad("未指定网关：用 --server 或配置 server.host")
	}
	if c.Server.Port < 1 || c.Server.Port > 65535 {
		return bad("server.port=%d 超出 1–65535", c.Server.Port)
	}
	if c.Tunnel.MTU < 576 || c.Tunnel.MTU > 1500 {
		return bad("tunnel.mtu=%d 超出 576–1500", c.Tunnel.MTU)
	}
	switch c.Tunnel.Transport {
	case "tcp", "udp":
	default:
		return bad("tunnel.transport=%q，应为 tcp 或 udp", c.Tunnel.Transport)
	}
	switch c.Tunnel.TokenEncoding {
	case "ascii", "hex":
	default:
		return bad("tunnel.token_encoding=%q，应为 ascii 或 hex", c.Tunnel.TokenEncoding)
	}
	switch c.Auth.SendDeviceID {
	case "auto", "always", "never":
	default:
		return bad("auth.send_device_id=%q，应为 auto/always/never", c.Auth.SendDeviceID)
	}
	if c.Tunnel.CtrlConnType < 0 || c.Tunnel.DataOpcode < 0 {
		return bad("tunnel.ctrl_conn_type / data_opcode 不能为负")
	}
	if c.Tunnel.HeartbeatTimeout.Duration <= 0 {
		return bad("tunnel.heartbeat_timeout 必须为正")
	}
	if _, err := logx.ParseLevel(c.Log.Level); err != nil {
		return bad("%v", err)
	}
	return nil
}
