// testserver：本地假网关，实现与真实网关相同的线格式（docs/11 §2）。
// 仅监听回环地址，供开发与 CI 使用，不要暴露到外网。
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/Sh-Fang/vpnkit/testserver"
)

func main() {
	httpAddr := flag.String("http", "127.0.0.1:8443", "HTTPS 认证端监听地址")
	tunnelAddr := flag.String("tunnel", "127.0.0.1:8444", "隧道监听地址")
	user := flag.String("user", "alice", "测试账号")
	password := flag.String("password", "secret", "测试密码（仅测试用）")
	routes := flag.String("rclist", "10.0.0.0/8;corp.example.com", "资源列表条目，分号分隔")
	certOut := flag.String("cert-out", "testserver-ca.pem", "把自签证书写到此文件，供 vpnkit --ca-file 使用")
	script := flag.String("script", "happy", "隧道剧本："+strings.Join(testserver.ScriptNames(), "|"))
	pswDiff := flag.Bool("psw-config-different-key", false, "psw_config 返回不同公钥")
	nextAuth := flag.String("next-auth", "", "登录后要求二次认证，如 4（特征码）")
	nextService := flag.String("next-service", "", "随 NextAuth 下发的服务名，如 auth/hid")
	hidExpect := flag.String("hid-expect", "", "期望的特征码；设置后只有该特征码能通过认证")
	flag.Parse()

	_, tportS, err := net.SplitHostPort(*tunnelAddr)
	if err != nil {
		log.Fatal(err)
	}
	tport, _ := strconv.Atoi(tportS)
	as, err := testserver.NewAuthServer(testserver.AuthConfig{
		Users:                 map[string]string{*user: *password},
		PswConfigDifferentKey: *pswDiff,
		NextAuth:              *nextAuth,
		NextService:           *nextService,
		HIDExpectDevID:        *hidExpect,
		ConfXML:               testserver.ConfXML(tport),
		RCList:                testserver.RCListXML(strings.Split(*routes, ";")...),
	})
	if err != nil {
		log.Fatal(err)
	}
	host, _, _ := net.SplitHostPort(*httpAddr)
	cert, pemBytes, err := testserver.SelfSignedCert(host, "localhost")
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(*certOut, pemBytes, 0o644); err != nil {
		log.Fatal(err)
	}

	ts, err := testserver.NewTunnelServer(testserver.TunnelConfig{Auth: as, Script: *script, Logf: log.Printf})
	if err != nil {
		log.Fatal(err)
	}
	tl, err := net.Listen("tcp", *tunnelAddr)
	if err != nil {
		log.Fatal(err)
	}
	go func() { log.Fatal(ts.Serve(tl)) }()

	srv := &http.Server{Addr: *httpAddr, Handler: as.Handler(), TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}}}
	fmt.Fprintf(os.Stderr, "testserver: https=%s tunnel=%s script=%s ca=%s\n", *httpAddr, *tunnelAddr, *script, *certOut)
	log.Fatal(srv.ListenAndServeTLS("", ""))
}
