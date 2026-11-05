package auth

import (
	"encoding/json"
	"regexp"
	"strings"
)

// extractFields 从响应体中提取指定字段（docs/02 §1.1）。
// 字段可能出现在 JSON、XML/HTML 或 JS 变量赋值中：先按 JSON 解析，失败再逐字段用正则兜底。
// 找不到的字段不出现在结果里，由调用方决定是否报格式错误——不静默返回空值。
func extractFields(body []byte, names ...string) map[string]string {
	out := map[string]string{}
	var obj map[string]any
	if json.Unmarshal(body, &obj) == nil {
		flattenJSON(obj, out)
		res := map[string]string{}
		for _, n := range names {
			if v, ok := lookupFold(out, n); ok {
				res[n] = v
			}
		}
		if len(res) > 0 {
			return res
		}
	}
	s := string(body)
	res := map[string]string{}
	for _, n := range names {
		if v, ok := regexField(s, n); ok {
			res[n] = v
		}
	}
	return res
}

var reOpenTag = regexp.MustCompile(`<([A-Za-z][\w.\-]*)(?:\s[^>]*)?>`)

// rootTag 返回正文首个元素的名字，判定不出时返回空。
//
// 网关用根元素区分三类回执：<Auth> 是状态回执（成功也是它，靠 ErrorCode 区分）、
// <Conf> 是配置、<Resource> 是资源列表。只按根元素判断，避免把配置里的同名字段当状态码
// （docs/02 §5.1）。
func rootTag(body []byte) string {
	if m := reOpenTag.FindStringSubmatch(string(body)); m != nil {
		return m[1]
	}
	return ""
}

var reCSRFVal = regexp.MustCompile(`(?is)(<CSRF_RAND_CODE>)[^<]*(</CSRF_RAND_CODE>)`)

// maskCSRFBody 把响应体里的 CSRF 值掩掉后返回，供 trace 打印完整 XML（含属性）而不泄露令牌。
func maskCSRFBody(body []byte) string {
	return reCSRFVal.ReplaceAllString(string(body), "${1}***${2}")
}

// tagNames 返回响应体中按首次出现顺序去重的 XML 标签名，只取名字、不取值，
// 用于二次认证探测（docs/02 §4）：联调时知道网关这一步声明了哪些字段，而不泄露任何令牌值。
func tagNames(body []byte) []string {
	var out []string
	seen := map[string]bool{}
	for _, m := range reOpenTag.FindAllStringSubmatch(string(body), -1) {
		name := m[1]
		if strings.EqualFold(name, "xml") || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	return out
}

func flattenJSON(m map[string]any, out map[string]string) {
	for k, v := range m {
		switch t := v.(type) {
		case string:
			out[k] = t
		case float64:
			out[k] = strings.TrimSuffix(strings.TrimRight(jsonNum(t), "0"), ".")
		case bool:
			if t {
				out[k] = "1"
			} else {
				out[k] = "0"
			}
		case map[string]any:
			flattenJSON(t, out)
		}
	}
}

func jsonNum(f float64) string {
	b, _ := json.Marshal(f)
	s := string(b)
	if !strings.Contains(s, ".") {
		s += "."
	}
	return s
}

func lookupFold(m map[string]string, name string) (string, bool) {
	if v, ok := m[name]; ok {
		return v, true
	}
	for k, v := range m {
		if strings.EqualFold(k, name) {
			return v, true
		}
	}
	return "", false
}

var reCache = map[string][]*regexp.Regexp{}

func regexField(s, name string) (string, bool) {
	res, ok := reCache[name]
	if !ok {
		q := regexp.QuoteMeta(name)
		res = []*regexp.Regexp{
			// <TwfID>abc</TwfID> 或 <TwfID><![CDATA[abc]]></TwfID>
			regexp.MustCompile(`(?is)<` + q + `>\s*(?:<!\[CDATA\[)?\s*([^<\]]*?)\s*(?:\]\]>)?\s*</` + q + `>`),
			// "TwfID": "abc" / 'TwfID': 123
			regexp.MustCompile(`(?i)["']` + q + `["']\s*:\s*["']?([^"',}\s]*)`),
			// var TwfID = "abc"; / TwfID=abc
			regexp.MustCompile(`(?i)\b` + q + `\s*=\s*["']?([^"'<;&,\s]*)`),
		}
		reCache[name] = res
	}
	for _, re := range res {
		if m := re.FindStringSubmatch(s); m != nil {
			return strings.TrimSpace(m[1]), true
		}
	}
	return "", false
}
