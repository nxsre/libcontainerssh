package config

import (
	"fmt"
	"github.com/ScaleFT/sshkeys"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"io"
	"log"
	"net"
	"os"
	"time"
)

type ProxyConfig struct {
	User         string        `json:"user" yaml:"user"`
	Server       string        `json:"server" yaml:"server"`
	Key          string        `json:"key" yaml:"key"`
	KeyPath      string        `json:"keyPath" yaml:"keyPath"`
	Port         string        `json:"port" yaml:"port"`
	Passphrase   string        `json:"passphrase" yaml:"passphrase"`
	Password     string        `json:"password" yaml:"password"`
	Timeout      time.Duration `json:"timeout" yaml:"timeout"`
	Ciphers      []string      `json:"ciphers" yaml:"ciphers"`
	KeyExchanges []string      `json:"keyExchanges" yaml:"keyExchanges"`
	Fingerprint  string        `json:"fingerprint" yaml:"fingerprint"`

	// Enable the use of insecure ciphers and key exchange methods.
	// This enables the use of the the following insecure ciphers and key exchange methods:
	// - aes128-cbc
	// - aes192-cbc
	// - aes256-cbc
	// - 3des-cbc
	// - diffie-hellman-group-exchange-sha256
	// - diffie-hellman-group-exchange-sha1
	// Those algorithms are insecure and may allow plaintext data to be recovered by an attacker.
	UseInsecureCipher bool `json:"useInsecureCipher" yaml:"useInsecureCipher"`
}

// returns ssh.Signer from user you running app home path + cutted key path.
// (ex. pubkey,err := getKeyFile("/.ssh/id_rsa") )
func getKeyFile(keypath, passphrase string) (ssh.Signer, error) {
	var pubkey ssh.Signer
	var err error
	buf, err := os.ReadFile(keypath)
	if err != nil {
		return nil, err
	}

	if passphrase != "" {
		pubkey, err = sshkeys.ParseEncryptedPrivateKey(buf, []byte(passphrase))
	} else {
		pubkey, err = ssh.ParsePrivateKey(buf)
	}

	if err != nil {
		return nil, err
	}

	return pubkey, nil
}

// returns *ssh.ClientConfig and io.Closer.
// if io.Closer is not nil, io.Closer.Close() should be called when
// *ssh.ClientConfig is no longer used.
func GetSSHConfig(config *ProxyConfig) (*ssh.ClientConfig, io.Closer) {
	var sshAgent io.Closer

	// auths holds the detected ssh auth methods
	auths := []ssh.AuthMethod{}

	// figure out what auths are requested, what is supported
	if config.Password != "" {
		auths = append(auths, ssh.Password(config.Password))
	}
	if config.KeyPath != "" {
		if pubkey, err := getKeyFile(config.KeyPath, config.Passphrase); err != nil {
			log.Printf("getKeyFile error: %v\n", err)
		} else {
			auths = append(auths, ssh.PublicKeys(pubkey))
		}
	}

	if config.Key != "" {
		var signer ssh.Signer
		var err error
		if config.Passphrase != "" {
			signer, err = sshkeys.ParseEncryptedPrivateKey([]byte(config.Key), []byte(config.Passphrase))
		} else {
			signer, err = ssh.ParsePrivateKey([]byte(config.Key))
		}

		if err != nil {
			log.Printf("ssh.ParsePrivateKey: %v\n", err)
		} else {
			auths = append(auths, ssh.PublicKeys(signer))
		}
	}

	if sshAgent, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK")); err == nil {
		auths = append(auths, ssh.PublicKeysCallback(agent.NewClient(sshAgent).Signers))
	}

	c := ssh.Config{}
	if config.UseInsecureCipher {
		c.SetDefaults()
		c.Ciphers = append(c.Ciphers, "aes128-cbc", "aes192-cbc", "aes256-cbc", "3des-cbc")
		c.KeyExchanges = append(c.KeyExchanges, "diffie-hellman-group-exchange-sha1", "diffie-hellman-group-exchange-sha256")
	}

	if len(config.Ciphers) > 0 {
		c.Ciphers = append(c.Ciphers, config.Ciphers...)
	}

	if len(config.KeyExchanges) > 0 {
		c.KeyExchanges = append(c.KeyExchanges, config.KeyExchanges...)
	}

	hostKeyCallback := ssh.InsecureIgnoreHostKey()
	if config.Fingerprint != "" {
		hostKeyCallback = func(hostname string, remote net.Addr, publicKey ssh.PublicKey) error {
			if ssh.FingerprintSHA256(publicKey) != config.Fingerprint {
				return fmt.Errorf("ssh: host key fingerprint mismatch")
			}
			return nil
		}
	}

	return &ssh.ClientConfig{
		Config:          c,
		Timeout:         config.Timeout,
		User:            config.User,
		Auth:            auths,
		HostKeyCallback: hostKeyCallback,
	}, sshAgent
}
