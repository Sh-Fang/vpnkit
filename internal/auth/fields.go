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
