package local

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
)

func init() {
	var worker, runsc bool
	flag.BoolVar(&runsc, "runsc", false, "")

	for _, arg := range os.Args {
		if strings.HasSuffix(arg, "-worker") {
			worker = true
		}
		if strings.HasSuffix(arg, "-runsc") {
			runsc = true
		}
	}

	if worker {
		return
	}

	logPath := "/var/log/odv"
	os.MkdirAll(logPath, 0777)
	os.Chmod(logPath, 0777)

	// hostkey
	keyPath := "/etc/ssh/keys"
	os.MkdirAll(keyPath, os.ModeDir)
	for _, t := range []string{RSA, ED25519, DSA, ECDSA} {
		//On the SSH client, the host-key algorithms that are supported when talking to a server are:
		//RSA: Equal or greater-than to 1024 bit
		//ECDSA: 256, 384, or 521 bit
		//ED25519: 256 bit
		//DSS: 1024 bit
		//On the SSH server, the host-key algorithms that are generated and stored are:
		//RSA: 2048 bit
		//ECDSA: 256 bit (Prior to Junos OS Release 22.3R1).
		//ECDSA: 256, 384, or 521 bit (Starting in Junos OS Release 22.3R1).
		//ED25519: 256 bit
		//DSS: 1024 bit

		filename := filepath.Join(keyPath, fmt.Sprintf("ssh_host_%s_key", t))
		if !Exists(filename) {
			// seed  "abcdefg"
			fmt.Println("生成 hostkey:", filename)
			var seeder io.Reader
			var keydgen *Keydgen
			switch t {
			case RSA:
				seeder, _ = NewSeeder([]byte("abcdefg"), 10, 3, 1024*16, 1)
				keydgen = &Keydgen{Type: t, Bits: 2048, Curve: 0}
			case ED25519:
				seeder, _ = NewSeeder([]byte("abcdefg"), 1000, 3, 1024*16, 1)
				keydgen = &Keydgen{Type: t, Bits: 0, Curve: 0}
			case DSA:
				seeder, _ = NewSeeder([]byte("abcdefg"), 1000, 3, 1024*16, 1)
				keydgen = &Keydgen{Type: t, Bits: 1024, Curve: 0}
			case ECDSA:
				seeder, _ = NewSeeder([]byte("abcdefg"), 1000, 3, 1024*16, 1)
				keydgen = &Keydgen{Type: t, Bits: 0, Curve: 224}
			}
			_, err := keydgen.GenerateKey(seeder)
			if err != nil {
				log.Fatalln(err)
			}

			err = writeKeyPairToFile(keydgen, filename)
			if err != nil {
				log.Fatalln(err)
			}
		}
	}
	// userkey
	if !Exists(priKeyFile) && !Exists(pubKeyFile) {
		fmt.Println("生成 ssh 秘钥对：", priKeyFile)
		genKeyPair(priKeyFile, pubKeyFile)
	}

	// 启动 vscode 运行容器
	// TODO: 根据运行环境判断是否需要启动
	go func() {
		if !vscodeContainerRunning && runsc {
			log.Println("启动 runsc")
			if err := createVscodeContainer(containerName); err != nil {
				fmt.Println("启动失败", err)
			}

			vscodeContainerRunning = true
		}
	}()
}

// 判断所给路径文件/文件夹是否存在
func Exists(path string) bool {
	_, err := os.Stat(path) //os.Stat获取文件信息
	if err != nil {
		if os.IsExist(err) {
			return true
		}
		return false
	}
	return true
}

// 判断所给路径是否为文件夹
func IsDir(path string) bool {
	s, err := os.Stat(path)
	if err != nil {
		return false
	}
	return s.IsDir()
}

// 判断所给路径是否为文件
func IsFile(path string) bool {
	return !IsDir(path)
}
