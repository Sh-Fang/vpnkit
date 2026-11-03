package config

import (
	"fmt"
	"strconv"
	"strings"
)

// parseTOML 解析 docs/09 用到的 TOML 子集：[section]、key = 值、# 注释；
// 值支持 "基本字符串"、'字面字符串'、整数、布尔、单行或多行数组。
// 依赖白名单不允许引入第三方 TOML 库（AGENTS.md §3），而配置文件只需这么多。
func parseTOML(src string) (map[string]map[string]any, error) {
	out := map[string]map[string]any{"": {}}
	section := ""
	lines := strings.Split(strings.ReplaceAll(src, "\r\n", "\n"), "\n")
	for i := 0; i < len(lines); i++ {
		lineNo := i + 1
		line := strings.TrimSpace(stripComment(lines[i]))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") {
			if !strings.HasSuffix(line, "]") || strings.HasPrefix(line, "[[") {
				return nil, fmt.Errorf("第 %d 行: 不支持的段声明 %q", lineNo, line)
			}
			section = strings.TrimSpace(line[1 : len(line)-1])
			if _, ok := out[section]; !ok {
				out[section] = map[string]any{}
			}
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq <= 0 {
			return nil, fmt.Errorf("第 %d 行: 缺少 '='", lineNo)
		}
		key := strings.TrimSpace(line[:eq])
		val := strings.TrimSpace(line[eq+1:])
		// 多行数组：一直读到括号配平
		if strings.HasPrefix(val, "[") {
			for !bracketsClosed(val) {
				i++
				if i >= len(lines) {
					return nil, fmt.Errorf("第 %d 行: 数组未闭合", lineNo)
				}
				val += " " + strings.TrimSpace(stripComment(lines[i]))
			}
		}
		v, err := parseValue(val)
		if err != nil {
			return nil, fmt.Errorf("第 %d 行 %s: %w", lineNo, key, err)
		}
		if _, dup := out[section][key]; dup {
			return nil, fmt.Errorf("第 %d 行: 重复的键 %s", lineNo, key)
		}
		out[section][key] = v
	}
	return out, nil
}

// stripComment 去掉不在字符串内的 # 注释。
func stripComment(s string) string {
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == '\\' && quote == '"' {
				i++
			} else if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == '#':
			return s[:i]
		}
	}
	return s
}

func bracketsClosed(s string) bool {
	depth := 0
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == '\\' && quote == '"' {
				i++
			} else if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == '[':
			depth++
		case c == ']':
			depth--
		}
	}
	return depth == 0
}

func parseValue(s string) (any, error) {
	switch {
	case s == "":
		return nil, fmt.Errorf("缺少值")
	case s == "true":
		return true, nil
	case s == "false":
		return false, nil
	case s[0] == '"':
		str, rest, err := parseBasicString(s)
		if err != nil {
			return nil, err
		}
		if strings.TrimSpace(rest) != "" {
			return nil, fmt.Errorf("字符串后有多余内容 %q", rest)
		}
		return str, nil
	case s[0] == '\'':
		end := strings.IndexByte(s[1:], '\'')
		if end < 0 || strings.TrimSpace(s[end+2:]) != "" {
			return nil, fmt.Errorf("字面字符串格式错误")
		}
		return s[1 : end+1], nil
	case s[0] == '[':
		return parseArray(s)
	}
	n, err := strconv.ParseInt(strings.ReplaceAll(s, "_", ""), 0, 64)
	if err != nil {
		return nil, fmt.Errorf("无法识别的值 %q", s)
	}
	return n, nil
}

func parseBasicString(s string) (string, string, error) {
	var sb strings.Builder
	for i := 1; i < len(s); i++ {
		c := s[i]
		if c == '"' {
			return sb.String(), s[i+1:], nil
		}
		if c != '\\' {
			sb.WriteByte(c)
			continue
		}
		i++
		if i >= len(s) {
			break
		}
		switch s[i] {
		case 'n':
			sb.WriteByte('\n')
		case 't':
			sb.WriteByte('\t')
		case '\\', '"':
			sb.WriteByte(s[i])
		default:
			return "", "", fmt.Errorf("不支持的转义 \\%c", s[i])
		}
	}
	return "", "", fmt.Errorf("字符串未闭合")
}

func parseArray(s string) ([]any, error) {
	inner := strings.TrimSpace(s[1 : len(s)-1])
	var out []any
	for inner != "" {
		var item string
		if inner[0] == '"' {
			str, rest, err := parseBasicString(inner)
			if err != nil {
				return nil, err
			}
			out = append(out, str)
			inner = strings.TrimSpace(rest)
		} else if inner[0] == '\'' {
			end := strings.IndexByte(inner[1:], '\'')
			if end < 0 {
				return nil, fmt.Errorf("字面字符串未闭合")
			}
			out = append(out, inner[1:end+1])
			inner = strings.TrimSpace(inner[end+2:])
		} else {
			comma := strings.IndexByte(inner, ',')
			if comma < 0 {
				item, inner = inner, ""
			} else {
				item, inner = inner[:comma], inner[comma:]
			}
			v, err := parseValue(strings.TrimSpace(item))
			if err != nil {
				return nil, err
			}
			out = append(out, v)
			inner = strings.TrimSpace(inner)
		}
		if strings.HasPrefix(inner, ",") {
			inner = strings.TrimSpace(inner[1:])
		} else if inner != "" {
			return nil, fmt.Errorf("数组元素之间缺少逗号")
		}
	}
	return out, nil
}
