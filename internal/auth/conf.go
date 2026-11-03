package auth

import (
	"encoding/xml"
	"net"
	"strconv"
	"strings"
)

// Conf 是 conf.csp 中本项目用到的字段（docs/09 §3）。
type Conf struct {
	MlineEnabled bool
	Lines        []string // host:port 候选线路
	MTU          int
	Port         int
	RecvLimit    int64
	SendLimit    int64
	Compress     int
	MaxSession   int
	TunDNS       []string
	IsHidUser    int
	IsHidUserSet bool // 缺失时按 0 处理，并由调用方打 info（docs/09 §3）
	LoginName    string
}

type xmlConf struct {
	Mline *struct {
		Enable string `xml:"enable,attr"`
		List   string `xml:"list,attr"`
	} `xml:"Mline"`
	Htp *struct {
		Port string `xml:"port,attr"`
		MTU  string `xml:"mtu,attr"`
	} `xml:"Htp"`
	Bandwidth *struct {
		Recv string `xml:"recvlimit,attr"`
		Send string `xml:"sendlimit,attr"`
	} `xml:"Bandwidth"`
	TcpApplication *struct {
		Compress   string `xml:"compress,attr"`
		MaxSession string `xml:"maxsession,attr"`
	} `xml:"TcpApplication"`
	L3VPN *struct {
		DNS    string `xml:"iptunDns,attr"`
		DNSBak string `xml:"iptunDnsBak,attr"`
	} `xml:"L3VPN"`
	Other *struct {
		LoginName string  `xml:"login_name,attr"`
		IsHidUser *string `xml:"isHidUser,attr"`
	} `xml:"Other"`
}

// ParseConf 容错解析：缺失节点用默认值，未知节点忽略，不假设顺序（docs/09 §3）。
// 返回的 warnings 描述被降级处理的问题。
func ParseConf(body []byte) (Conf, []string) {
	var c Conf
	var warns []string
	var x xmlConf
	if err := xml.Unmarshal(body, &x); err != nil {
		return c, []string{"conf.csp 不是合法 XML，全部使用默认值: " + err.Error()}
	}
	if x.Mline != nil {
		c.MlineEnabled = x.Mline.Enable == "1"
		for _, l := range strings.Split(x.Mline.List, ";") {
			l = strings.TrimSpace(l)
			if l == "" {
				continue
			}
			if _, _, err := net.SplitHostPort(l); err != nil {
				warns = append(warns, "忽略非法线路 "+l)
				continue
			}
			c.Lines = append(c.Lines, l)
		}
	}
	if x.Htp != nil {
		c.Port = atoi(x.Htp.Port)
		c.MTU = atoi(x.Htp.MTU)
	}
	if x.Bandwidth != nil {
		c.RecvLimit = int64(atoi(x.Bandwidth.Recv))
		c.SendLimit = int64(atoi(x.Bandwidth.Send))
	}
	if x.TcpApplication != nil {
		c.Compress = atoi(x.TcpApplication.Compress)
		c.MaxSession = atoi(x.TcpApplication.MaxSession)
	}
	if x.L3VPN != nil {
		for _, d := range []string{x.L3VPN.DNS, x.L3VPN.DNSBak} {
			if ip := net.ParseIP(strings.TrimSpace(d)); ip != nil && !ip.IsUnspecified() && ip.To4() != nil {
				c.TunDNS = append(c.TunDNS, ip.String())
			}
		}
	}
	if x.Other != nil {
		c.LoginName = x.Other.LoginName
		if x.Other.IsHidUser != nil {
			c.IsHidUser = atoi(*x.Other.IsHidUser)
			c.IsHidUserSet = true
		}
	}
	return c, warns
}

func atoi(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}
