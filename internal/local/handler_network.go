package local

import (
	"bufio"
	"context"
	"fmt"
	"github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"
	"gorm.io/gorm"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	auth2 "go.containerssh.io/libcontainerssh/auth"
	"go.containerssh.io/libcontainerssh/internal/agentforward"
	"go.containerssh.io/libcontainerssh/internal/sshserver"
	"go.containerssh.io/libcontainerssh/log"
	"go.containerssh.io/libcontainerssh/metadata"
)

type networkHandler struct {
	sshserver.AbstractNetworkConnectionHandler

	mutex             *sync.Mutex
	client            net.TCPAddr
	username          string
	connectionID      string
	logger            log.Logger
	disconnected      bool
	labels            map[string]string
	done              chan struct{}
	db                *gorm.DB
	connectionHandler *sshConnectionHandler
}

func (n *networkHandler) OnAuthPassword(meta metadata.ConnectionAuthPendingMetadata, _ []byte) (
	sshserver.AuthResponse,
	metadata.ConnectionAuthenticatedMetadata,
	error,
) {
	return sshserver.AuthResponseUnavailable, meta.AuthFailed(), fmt.Errorf("docker does not support authentication")
}

func (n *networkHandler) OnAuthPubKey(
	meta metadata.ConnectionAuthPendingMetadata,
	_ auth2.PublicKey,
) (sshserver.AuthResponse, metadata.ConnectionAuthenticatedMetadata, error) {
	return sshserver.AuthResponseUnavailable, meta.AuthFailed(), fmt.Errorf("docker does not support authentication")
}

func (n *networkHandler) OnHandshakeFailed(metadata.ConnectionMetadata, error) {}

func (n *networkHandler) OnHandshakeSuccess(meta metadata.ConnectionAuthenticatedMetadata, sshCtx ssh.Context) (
	connection sshserver.SSHConnectionHandler,
	metadata metadata.ConnectionAuthenticatedMetadata,
	failureReason error,
) {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	ctx, cancelFunc := context.WithTimeout(
		context.Background(),
		6*time.Second,
	)
	_ = ctx
	defer cancelFunc()
	n.username = meta.Username
	env := map[string]string{}
	for k, v := range meta.GetEnvironment() {
		env[k] = v.Value
	}
	n.connectionHandler = &sshConnectionHandler{
		networkHandler: n,
		username:       meta.Username,
		env:            env,
		agentForward:   agentforward.NewAgentForward(n.logger),
		ctx:            sshCtx,
	}

	// 为安全容器建连接备用
	key, err := os.ReadFile(priKeyFile)
	if err != nil {
		n.logger.Error(err)
		return
	}

	signer, err := gossh.ParsePrivateKey(key)
	if err != nil {
		n.logger.Error(err)
		return
	}

	entry, _ := user.Lookup(n.username)
	// 初始化免密环境
	sshDir := filepath.Join(entry.HomeDir, ".ssh")
	os.MkdirAll(sshDir, os.ModeDir)
	uid, _ := strconv.Atoi(entry.Uid)
	gid, _ := strconv.Atoi(entry.Gid)
	os.Chown(sshDir, uid, gid)

	authorizedKeysfile := filepath.Join(sshDir, "authorized_keys")
	if !Exists(authorizedKeysfile) {
		//	添加 authorized_keys
		file, err := os.OpenFile(authorizedKeysfile, os.O_APPEND|os.O_CREATE, 0600)
		if err != nil {
			panic(err)
		}
		file.Write(signer.PublicKey().Marshal())
		file.Close()
		os.Chown(authorizedKeysfile, uid, gid)
	}

	authorizedKeysBytes, err := os.ReadFile(authorizedKeysfile)
	authorizedKeysMap := map[string]bool{}
	for len(authorizedKeysBytes) > 0 {
		pubKey, _, _, rest, err := ssh.ParseAuthorizedKey(authorizedKeysBytes)
		if err != nil {
			n.logger.Error(err)
			return
		}

		authorizedKeysMap[string(pubKey.Marshal())] = true
		authorizedKeysBytes = rest
	}

	if _, ok := authorizedKeysMap[string(signer.PublicKey().Marshal())]; !ok {
		//	添加 authorized_keys
		file, err := os.OpenFile(authorizedKeysfile, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0600)
		if err != nil {
			return
		}
		write := bufio.NewWriter(file)
		bs, err := os.ReadFile(pubKeyFile)
		if err != nil {
			return
		}
		write.Write(bs)
		write.Flush()
		file.Close()
		os.Chown(authorizedKeysfile, uid, gid)
	}

	// 建立SSH客户端连接
	client, err := gossh.Dial("tcp", "127.0.0.1:1022", &gossh.ClientConfig{
		User:            n.username,
		Auth:            []gossh.AuthMethod{gossh.PublicKeys(signer)},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
	})

	if err != nil {
		n.logger.Error(err)
	}
	n.connectionHandler.sshClient = client

	return n.connectionHandler, meta, nil
}

func (n *networkHandler) OnDisconnect() {
	// display 不为空时需要关闭 agent，回收 display 资源
	if n.connectionHandler.display != nil {
		if n.connectionHandler.agentCmd != nil {
			if n.connectionHandler.agentCmd.Process != nil {
				n.connectionHandler.agentCmd.Process.Kill()
				n.connectionHandler.agentCmd.Wait()
			}
		}
		n.connectionHandler.display.Lock = 0
		n.db.Save(n.connectionHandler.display)

		if n.connectionHandler.agentForward != nil {
			n.connectionHandler.agentForward.OnShutdown()
		}
	}

	n.mutex.Lock()
	defer n.mutex.Unlock()
	if n.disconnected {
		return
	}
	n.disconnected = true
	close(n.done)
}

func (n *networkHandler) OnShutdown(shutdownContext context.Context) {
	select {
	case <-shutdownContext.Done():
		n.OnDisconnect()
	case <-n.done:
	}
}

func (n *networkHandler) Context() ssh.Context {
	return n.connectionHandler.Context()
}
