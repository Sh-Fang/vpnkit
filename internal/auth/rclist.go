package auth

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Resources 是从资源列表归一化得到的分流目标（docs/09 §4）。
type Resources struct {
	Prefixes []netip.Prefix // 内网网段，已去重并合并被包含的条目
	Suffixes []string       // 内网域名后缀
	Skipped  []string       // 无法识别的条目（供日志）
}

var (
	reRcTag   = regexp.MustCompile(`(?is)<Rc\b[^>]*>`)
	reHostAtt = regexp.MustCompile(`(?i)\bhost\s*=\s*"([^"]*)"`)
)

// ParseResources 解析 rclist.csp。
//
// docs/09 §4 只规定了"资源 → 目标地址/掩码 → CIDR"，未给出报文格式，属假设点 rclist_format。
// 当前实现：优先取 <Rc ... host="a;b;c"> 的 host 属性；没有 <Rc> 元素时按行/分号逐条解析纯文本。
// 每个条目支持 CIDR、IP/点分掩码、单 IP、a~b 或 a-b 地址段、域名（含 *. 前缀）、可带 scheme 与端口。
func ParseResources(body []byte) (format string, entries []string) {
	s := string(body)
	if tags := reRcTag.FindAllString(s, -1); len(tags) > 0 {
		for _, t := range tags {
			if m := reHostAtt.FindStringSubmatch(t); m != nil {
				entries = append(entries, splitEntries(m[1])...)
			}
		}
		return "xml-rc-host", entries
	}
	return "plain-lines", splitEntries(s)
}

func splitEntries(s string) []string {
	var out []string
	var kept []string
	for _, line := range strings.Split(s, "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		kept = append(kept, line)
	}
	s = strings.Join(kept, "\n")
	for _, e := range strings.FieldsFunc(s, func(r rune) bool {
		return r == ';' || r == ',' || r == '\n' || r == '\r' || r == ' ' || r == '\t'
	}) {
		if e = strings.TrimSpace(e); e != "" {
			out = append(out, e)
		}
	}
	return out
}

// Normalize 把原始条目归一化为网段与域名后缀。
func Normalize(entries []string) Resources {
	var r Resources
	var prefixes []netip.Prefix
	seenSuffix := map[string]bool{}
	for _, raw := range entries {
		ps, suffix, err := classify(raw)
		switch {
		case err != nil:
			r.Skipped = append(r.Skipped, raw)
		case suffix != "":
			if !seenSuffix[suffix] {
				seenSuffix[suffix] = true
				r.Suffixes = append(r.Suffixes, suffix)
			}
		default:
			prefixes = append(prefixes, ps...)
		}
	}
	r.Prefixes = MergePrefixes(prefixes)
	return r
}

// MergePrefixes 去重并删除被其他网段包含的条目。
// 结果按前缀长度升序、地址升序排列，输出稳定，便于 down 后比对。
func MergePrefixes(in []netip.Prefix) []netip.Prefix {
	ps := make([]netip.Prefix, 0, len(in))
	for _, p := range in {
		ps = append(ps, p.Masked())
	}
	sort.Slice(ps, func(i, j int) bool {
		if ps[i].Bits() != ps[j].Bits() {
			return ps[i].Bits() < ps[j].Bits()
		}
		return ps[i].Addr().Less(ps[j].Addr())
	})
	var out []netip.Prefix
next:
	for _, p := range ps {
		for _, q := range out {
			if q.Bits() <= p.Bits() && q.Contains(p.Addr()) {
				continue next
			}
		}
		out = append(out, p)
	}
	return out
}

func classify(raw string) ([]netip.Prefix, string, error) {
	s := strings.TrimSpace(raw)
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexByte(s, '/'); i >= 0 {
		// 可能是 CIDR，也可能是 URL 路径
		if p, err := parseCIDRish(s); err == nil {
			return []netip.Prefix{p}, "", nil
		}
		s = s[:i]
	}
	s = stripPort(s)
	if s == "" {
		return nil, "", fmt.Errorf("空条目")
	}
	for _, sep := range []string{"~", "-"} {
		if a, b, ok := strings.Cut(s, sep); ok {
			lo, err1 := netip.ParseAddr(strings.TrimSpace(a))
			hi, err2 := netip.ParseAddr(strings.TrimSpace(b))
			if err1 == nil && err2 == nil {
				ps, err := RangeToPrefixes(lo, hi)
				return ps, "", err
			}
		}
	}
	if a, err := netip.ParseAddr(s); err == nil {
		if !a.Is4() {
			return nil, "", fmt.Errorf("暂不支持 IPv6")
		}
		return []netip.Prefix{netip.PrefixFrom(a, 32)}, "", nil
	}
	if d := normalizeDomain(s); d != "" {
		return nil, d, nil
	}
	return nil, "", fmt.Errorf("无法识别")
}

func stripPort(s string) string {
	if i := strings.LastIndexByte(s, ':'); i >= 0 && strings.Count(s, ":") == 1 {
		port := s[i+1:]
		if _, err := strconv.Atoi(strings.Split(port, "-")[0]); err == nil || port == "" {
			return s[:i]
		}
	}
	return s
}

func parseCIDRish(s string) (netip.Prefix, error) {
	addr, mask, _ := strings.Cut(s, "/")
	a, err := netip.ParseAddr(addr)
	if err != nil || !a.Is4() {
		return netip.Prefix{}, fmt.Errorf("bad addr")
	}
	if bits, err := strconv.Atoi(mask); err == nil {
		if bits < 0 || bits > 32 {
			return netip.Prefix{}, fmt.Errorf("bad bits")
		}
		return netip.PrefixFrom(a, bits).Masked(), nil
	}
	m, err := netip.ParseAddr(mask)
	if err != nil || !m.Is4() {
		return netip.Prefix{}, fmt.Errorf("bad mask")
	}
	mv := binary.BigEndian.Uint32(m.AsSlice())
	bits := 0
	for mv&0x80000000 != 0 {
		bits++
		mv <<= 1
	}
	if mv != 0 {
		return netip.Prefix{}, fmt.Errorf("非连续掩码")
	}
	return netip.PrefixFrom(a, bits).Masked(), nil
}

// RangeToPrefixes 把闭区间 [lo, hi] 拆成最少的 CIDR。
func RangeToPrefixes(lo, hi netip.Addr) ([]netip.Prefix, error) {
	if !lo.Is4() || !hi.Is4() {
		return nil, fmt.Errorf("仅支持 IPv4 地址段")
	}
	a := uint64(binary.BigEndian.Uint32(lo.AsSlice()))
	b := uint64(binary.BigEndian.Uint32(hi.AsSlice()))
	if a > b {
		return nil, fmt.Errorf("地址段起点大于终点")
	}
	var out []netip.Prefix
	for a <= b {
		size := uint64(1)
		bits := 32
		for bits > 0 {
			next := size << 1
			if a%next != 0 || a+next-1 > b {
				break
			}
			size = next
			bits--
		}
		var buf [4]byte
		binary.BigEndian.PutUint32(buf[:], uint32(a))
		out = append(out, netip.PrefixFrom(netip.AddrFrom4(buf), bits))
		a += size
	}
	return out, nil
}

var reDomain = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)

func normalizeDomain(s string) string {
	d := strings.ToLower(strings.TrimSpace(s))
	d = strings.TrimPrefix(d, "*.")
	d = strings.Trim(d, ".")
	if reDomain.MatchString(d) {
		return d
	}
	return ""
}
