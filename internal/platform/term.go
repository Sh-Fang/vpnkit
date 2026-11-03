// Package platform 封装三平台差异（docs/08）：终端、TUN、权限、信号。
// 本包不得 import 任何业务包（docs/01 §1）。
package platform

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

var ErrNotTerminal = errors.New("标准输入不是终端，无法交互输入密码；可设置 VPNKIT_PASSWORD")

// ReadPassword 在终端关闭回显后读取一行。密码只经过内存，不进 argv、不进日志（docs/00 §5 P1）。
func ReadPassword(prompt string, out io.Writer) (string, error) {
	fd := int(os.Stdin.Fd())
	if !isTerminal(fd) {
		return "", ErrNotTerminal
	}
	fmt.Fprint(out, prompt)
	restore, err := disableEcho(fd)
	if err != nil {
		return "", err
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	restore()
	fmt.Fprintln(out)
	if err != nil && !(errors.Is(err, io.EOF) && line != "") {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}
