package sshproxy

import (
	"context"
	"fmt"
	"github.com/gliderlabs/ssh"
	"net"
	"sync"
	"time"

	auth2 "go.containerssh.io/libcontainerssh/auth"
	"go.containerssh.io/libcontainerssh/config"
	"go.containerssh.io/libcontainerssh/internal/auth"
	"go.containerssh.io/libcontainerssh/internal/metrics"
	"go.containerssh.io/libcontainerssh/log"
	"go.containerssh.io/libcontainerssh/message"
	"go.containerssh.io/libcontainerssh/metadata"

	gossh "golang.org/x/crypto/ssh"

	"go.containerssh.io/libcontainerssh/internal/sshserver"
)

type networkConnectionHandler struct {
	lock                  *sync.Mutex
	wg                    *sync.WaitGroup
	client                net.TCPAddr
	connectionID          string
	config                config.SSHProxyConfig
	logger                log.Logger
	backendRequestsMetric metrics.SimpleCounter
	backendFailuresMetric metrics.SimpleCounter
	tcpConn               net.Conn
	disconnected          bool
	privateKey            gossh.Signer
	proyClient            *gossh.Client
	done                  bool
	ctx                   ssh.Context
}

func (s *networkConnectionHandler) OnAuthPassword(meta metadata.ConnectionAuthPendingMetadata, password []byte) (
	_ sshserver.AuthResponse,
	_ metadata.ConnectionAuthenticatedMetadata,
	_ error,
) {
	s.logger.Info("password:::", string(password))
	return sshserver.AuthResponseUnavailable, meta.AuthFailed(), fmt.Errorf(
		"ssh proxy does not support authentication",
	)
}

func (s *networkConnectionHandler) OnAuthPubKey(meta metadata.ConnectionAuthPendingMetadata, _ auth2.PublicKey) (
	sshserver.AuthResponse,
	metadata.ConnectionAuthenticatedMetadata,
	error,
) {
	return sshserver.AuthResponseUnavailable, meta.AuthFailed(), fmt.Errorf(
		"ssh proxy does not support authentication",
	)
}

func (s *networkConnectionHandler) OnAuthKeyboardInteractive(
	meta metadata.ConnectionAuthPendingMetadata,
	_ func(
	_ string,
	_ sshserver.KeyboardInteractiveQuestions,
) (answers sshserver.KeyboardInteractiveAnswers, err error),
) (sshserver.AuthResponse, metadata.ConnectionAuthenticatedMetadata, error) {
	return sshserver.AuthResponseUnavailable, meta.AuthFailed(), fmt.Errorf(
		"ssh proxy does not support authentication",
	)
}

func (s *networkConnectionHandler) OnAuthGSSAPI(_ metadata.ConnectionMetadata) auth.GSSAPIServer {
	return nil
}

func (s *networkConnectionHandler) OnHandshakeFailed(_ metadata.ConnectionMetadata, _ error) {}

func (s *networkConnectionHandler) OnHandshakeSuccess(
	meta metadata.ConnectionAuthenticatedMetadata,
	ctx ssh.Context,
) (
	connection sshserver.SSHConnectionHandler,
	metadata metadata.ConnectionAuthenticatedMetadata,
	failureReason error,
) {
	s.lock.Lock()
	defer s.lock.Unlock()
	if s.disconnected {
		return nil, meta, message.NewMessage(
			message.ESSHProxyDisconnected,
			"could not connect to backend because the user already disconnected",
		)
	}
	s.logger.Debug(fmt.Sprintf("%+v", meta))
	sshConn, newChannels, requests, err := s.createBackendSSHConnection(meta.Username, meta.Metadata["password"], meta.Metadata["pubKey"])
	if err != nil {
		return nil, meta, err
	}

	sshConnectionHandler := &sshConnectionHandler{
		networkHandler: s,
		sshConn:        sshConn,
		logger:         s.logger,
		ctx:            ctx,
	}
	go sshConnectionHandler.handleChannels(newChannels)
	go sshConnectionHandler.handleRequests(requests)

	return sshConnectionHandler, meta, nil
}

func (s *networkConnectionHandler) createBackendSSHConnection(username string, password, pubkey metadata.Value) (
	gossh.Conn,
	<-chan gossh.NewChannel,
	<-chan *gossh.Request,
	error,
) {
	s.backendRequestsMetric.Increment()
	target := fmt.Sprintf("%s:%d", s.config.Server, s.config.Port)
	proyClient, tcpConn, err := s.createBackendTCPConnection(username, target)
	if err != nil {
		return nil, nil, nil, err
	}
	s.tcpConn = tcpConn
	s.proyClient = proyClient
	sshClientConfig := s.createClientConfig(username, password.Value, pubkey.Value)

	sshConn, newChannels, requests, err := gossh.NewClientConn(s.tcpConn, target, sshClientConfig)
	if err != nil {
		s.backendFailuresMetric.Increment(metrics.Label("failure", "handshake"))
		return nil, nil, nil, message.WrapUser(
			err,
			message.ESSHProxyBackendHandshakeFailed,
			"SSH service is currently unavailable.",
			"Failed to authenticate with the backend.",
		).Label("backend", target)
	}

	return sshConn, newChannels, requests, nil
}

func (s *networkConnectionHandler) createClientConfig(username, password, pubkey string) *gossh.ClientConfig {
	if !s.config.UsernamePassThrough {
		username = s.config.Username
	}

	authMethods := []gossh.AuthMethod{}
	if password != "" {
		authMethods = append(authMethods,
			//ssh.Password(s.config.Password),
			gossh.Password(password),
		)
	}

	s.logger.Debug(password, pubkey)
	// 验证用户公钥
	keysMap := map[string]bool{}
	for _, key := range s.config.PubKeys {
		userKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(key))
		if err != nil {
			s.logger.Error(key, err)
			continue
		}

		keysMap[string(userKey.Marshal())] = true
	}

	reqKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pubkey))
	if err != nil {
		s.logger.Error(err)
	} else {
		if _, ok := keysMap[string(reqKey.Marshal())]; ok {
			if true {
				if s.privateKey != nil {
					authMethods = append(
						authMethods, gossh.PublicKeys(
							s.privateKey,
						),
					)
				}
			}
		}
	}

	sshClientConfig := &gossh.ClientConfig{
		Config: gossh.Config{
			KeyExchanges: s.config.KexAlgorithms.StringList(),
			Ciphers:      s.config.Ciphers.StringList(),
			MACs:         s.config.MACs.StringList(),
		},
		User: username,
		Auth: authMethods,
		HostKeyCallback: func(hostname string, remote net.Addr, key gossh.PublicKey) error {
			if !s.config.StrictHostKeyChecking {
				return nil
			}

			fingerprint := gossh.FingerprintSHA256(key)

			for _, fp := range s.config.AllowedHostKeyFingerprints {
				if fingerprint == fp {
					return nil
				}
			}
			err := message.UserMessage(
				message.ESSHProxyInvalidFingerprint,
				"SSH service currently unavailable",
				"invalid host key fingerprint: %s",
				fingerprint,
			).Label("fingerprint", fingerprint)
			s.logger.Error(err)
			return err
		},
		ClientVersion:     s.config.ClientVersion.String(),
		HostKeyAlgorithms: s.config.HostKeyAlgorithms.StringList(),
		Timeout:           s.config.Timeout,
	}
	return sshClientConfig
}

func (s *networkConnectionHandler) createBackendTCPConnection(
	_ string,
	target string,
) (*gossh.Client, net.Conn, error) {
	s.logger.Debug(message.NewMessage(message.MSSHProxyConnecting, "Connecting to backend server %s", target))
	ctx, cancelFunc := context.WithTimeout(context.Background(), s.config.Timeout)
	defer cancelFunc()
	var networkConnection net.Conn
	var lastError error
loop:
	for {
		if s.config.ProxyJump != nil {
			proxyConfig, closer := config.GetSSHConfig(s.config.ProxyJump)
			if closer != nil {
				defer closer.Close()
			}

			proxyClient, lastError := gossh.Dial("tcp", net.JoinHostPort(s.config.ProxyJump.Server, s.config.ProxyJump.Port), proxyConfig)
			if lastError != nil {
				continue
			}

			networkConnection, lastError = proxyClient.Dial("tcp", target)
			if lastError == nil {
				return proxyClient, networkConnection, nil
			}

		} else {
			networkConnection, lastError = net.Dial("tcp", target)
			if lastError == nil {
				return nil, networkConnection, nil
			}
		}

		s.backendFailuresMetric.Increment(metrics.Label("failure", "tcp"))
		s.logger.Debug(
			message.WrapUser(
				lastError,
				message.ESSHProxyBackendConnectionFailed,
				"service currently unavailable",
				"connection to SSH backend failed, retrying in 10 seconds",
			),
		)
		select {
		case <-ctx.Done():
			break loop
		case <-time.After(10 * time.Second):
		}
	}
	err := message.WrapUser(
		lastError,
		message.ESSHProxyBackendConnectionFailed,
		"service currently unavailable",
		"connection to SSH backend failed, giving up",
	)
	s.logger.Error(err)
	return nil, nil, err
}

func (s *networkConnectionHandler) OnDisconnect() {
	s.logger.Debug(
		message.NewMessage(
			message.MSSHProxyDisconnected,
			"Client disconnected, waiting for network connection lock...",
		),
	)
	s.lock.Lock()
	defer s.lock.Unlock()
	s.logger.Debug(
		message.NewMessage(
			message.MSSHProxyDisconnected,
			"Client disconnected, waiting for all sessions to terminate...",
		),
	)
	s.wg.Wait()
	s.done = true
	s.disconnected = true

	if s.tcpConn != nil {
		s.logger.Debug(message.NewMessage(message.MSSHProxyBackendDisconnecting, "Disconnecting backend connection..."))
		if err := s.tcpConn.Close(); err != nil {
			s.logger.Debug(
				message.Wrap(
					err,
					message.MSSHProxyBackendDisconnectFailed, "Failed to disconnect backend connection.",
				),
			)
		} else {
			s.logger.Debug(message.NewMessage(message.MSSHProxyBackendDisconnected, "Backend connection disconnected."))
		}
	} else {
		s.logger.Debug(
			message.NewMessage(
				message.MSSHProxyBackendDisconnected,
				"Backend connection already disconnected.",
			),
		)
	}
	if s.proyClient != nil {
		if err := s.proyClient.Close(); err != nil {
			s.logger.Debug(
				message.Wrap(
					err,
					message.MSSHProxyBackendDisconnectFailed, "Failed to disconnect proxyClient.",
				),
			)
		}
	} else {
		s.logger.Debug(message.NewMessage(message.MSSHProxyBackendDisconnected, "Backend proxyClient disconnected."))
	}
}

func (s *networkConnectionHandler) OnShutdown(_ context.Context) {}

func (s *networkConnectionHandler) Context() ssh.Context {
	return s.ctx
}
