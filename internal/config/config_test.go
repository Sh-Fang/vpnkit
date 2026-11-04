package config

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Sh-Fang/vpnkit/internal/fsutil"
	"github.com/Sh-Fang/vpnkit/internal/vpnerr"
)

const sample = `
# docs/09 §1 的示例
[server]
host      = "vpn.example.com"
port      = 443
auth      = "password"        # password | cert

[auth]
user           = "alice"
mitm_field     = "mitm"
send_rand_code = false

[tunnel]
mtu                = 1380
heartbeat_interval = "5s"
ctrl_conn_type     = 0
token_encoding     = "hex"

[split]
extra_routes = [
  "192.168.50.0/24", # 机房
  '10.9.0.0/16',
]

[dns]
suffixes = ["corp.example.com", "a#b.example.com"]
servers  = []

[log]
level = "trace"

[future]
x = 1
`

func TestLoadSample(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "config.toml")
	fsutil.WriteFile(p, []byte(sample))
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.Server.Host != "vpn.example.com" || c.Server.Port != 443 {
		t.Errorf("server %+v", c.Server)
	}
	if c.Auth.User != "alice" || c.Auth.MitmField != "mitm" || c.Auth.SendDeviceID != "auto" {
		t.Errorf("auth %+v", c.Auth)
	}
	if c.Tunnel.MTU != 1380 || c.Tunnel.HeartbeatInterval.Duration != 5*time.Second ||
		c.Tunnel.HeartbeatTimeout.Duration != 30*time.Second || c.Tunnel.CtrlConnType != 0 ||
		c.Tunnel.TokenEncoding != "hex" {
		t.Errorf("tunnel %+v", c.Tunnel)
	}
	if strings.Join(c.Split.ExtraRoutes, ",") != "192.168.50.0/24,10.9.0.0/16" {
		t.Errorf("routes %v", c.Split.ExtraRoutes)
	}
	if strings.Join(c.DNS.Suffixes, ",") != "corp.example.com,a#b.example.com" {
		t.Errorf("suffixes %v", c.DNS.Suffixes)
	}
	if len(c.Warnings) != 1 || !strings.Contains(c.Warnings[0], "future") {
		t.Errorf("warnings %v", c.Warnings)
	}
	if err := c.Validate(true); err != nil {
		t.Errorf("validate: %v", err)
	}
}

func TestLoadMissingDefaultOK(t *testing.T) {
	t.Setenv("VPNKIT_HOME", t.TempDir())
	t.Setenv("VPNKIT_CONFIG", "")
	c, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if c.Tunnel.CtrlConnType != 1 || c.Tunnel.ValidWait.Duration != 10*time.Second {
		t.Errorf("defaults %+v", c.Tunnel)
	}
}

func TestLoadMissingExplicitFails(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "nope.toml"))
	if !errors.Is(err, vpnerr.ErrUsage) {
		t.Fatalf("want usage error, got %v", err)
	}
}

func TestEnvOverride(t *testing.T) {
	t.Setenv("VPNKIT_HOME", t.TempDir())
	t.Setenv("VPNKIT_SERVER", "env.example.com")
	t.Setenv("VPNKIT_USER", "bob")
	c, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if c.Server.Host != "env.example.com" || c.Auth.User != "bob" {
		t.Fatalf("%+v %+v", c.Server, c.Auth)
	}
}

func TestBadValues(t *testing.T) {
	for _, src := range []string{
		"[server]\nport = \"x\"",
		"[tunnel]\nheartbeat_interval = 10",
		"[server]\nhost = \"a\"\nhost = \"b\"",
		"[split]\nextra_routes = [\"a\"",
		"[server]\nhost = \"unterminated",
	} {
		c := Default()
		if err := c.apply(src); err == nil {
			t.Errorf("expected error for %q", src)
		}
	}
}

func TestValidate(t *testing.T) {
	cases := []func(*Config){
		func(c *Config) { c.Server.Host = "" },
		func(c *Config) { c.Server.Port = 0 },
		func(c *Config) { c.Tunnel.MTU = 2000 },
		func(c *Config) { c.Tunnel.Transport = "quic" },
		func(c *Config) { c.Tunnel.TokenEncoding = "b64" },
		func(c *Config) { c.Auth.SendDeviceID = "maybe" },
		func(c *Config) { c.Log.Level = "loud" },
	}
	for i, mut := range cases {
		c := Default()
		c.Server.Host = "h"
		mut(c)
		if err := c.Validate(true); !errors.Is(err, vpnerr.ErrUsage) {
			t.Errorf("case %d: want usage error, got %v", i, err)
		}
	}
}
