package sshserver

import (
	"context"
	"errors"
	"fmt"
	"github.com/docker/docker/pkg/reexec"
	"github.com/gliderlabs/ssh"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	protocol "go.containerssh.io/libcontainerssh/agentprotocol"
	"go.containerssh.io/libcontainerssh/auth"
	"go.containerssh.io/libcontainerssh/config"
	ssh2 "go.containerssh.io/libcontainerssh/internal/ssh"
	"go.containerssh.io/libcontainerssh/log"
	messageCodes "go.containerssh.io/libcontainerssh/message"
	"go.containerssh.io/libcontainerssh/metadata"
	"go.containerssh.io/libcontainerssh/service"
	gossh "golang.org/x/crypto/ssh"
)

type connection struct {
	sshConn         *gossh.ServerConn
	reverseForwards map[string]*protocol.ForwardCtx
}

type serverImpl struct {
	cfg                 config.SSHConfig
	logger              log.Logger
	handler             Handler
	listenSocket        net.Listener
	wg                  *sync.WaitGroup
	lock                *sync.Mutex
	clientSockets       map[*gossh.ServerConn]bool
	connMap             map[string]connection
	nextGlobalRequestID uint64
	nextChannelID       uint64
	hostKeys            []gossh.Signer
	shutdownHandlers    *shutdownRegistry
	shuttingDown        bool
	configFile          string
}

func (s *serverImpl) String() string {
	return "SSH server"
}

func (s *serverImpl) WaitGroup() *sync.WaitGroup {
	return s.wg
}

func (s *serverImpl) RunWithLifecycle(lifecycle service.Lifecycle) error {
	s.lock.Lock()
	alreadyRunning := false
	if s.listenSocket != nil {
		alreadyRunning = true
	} else {
		s.clientSockets = make(map[*gossh.ServerConn]bool)
		s.connMap = make(map[string]connection)
	}
	s.shuttingDown = false
	if alreadyRunning {
		s.lock.Unlock()
		return messageCodes.NewMessage(messageCodes.ESSHAlreadyRunning, "SSH server is already running")
	}

	listenConfig := net.ListenConfig{
		Control: s.socketControl,
	}

	netListener, err := listenConfig.Listen(lifecycle.Context(), "tcp", s.cfg.Listen)
	if err != nil {
		s.lock.Unlock()
		return messageCodes.Wrap(err, messageCodes.ESSHStartFailed, "failed to start SSH server on %s", s.cfg.Listen)
	}
	s.listenSocket = netListener
	s.lock.Unlock()
	if err := s.handler.OnReady(); err != nil {
		if err := netListener.Close(); err != nil {
			s.logger.Warning(
				messageCodes.Wrap(
					err,
					messageCodes.ESSHListenCloseFailed,
					"failed to close listen socket after failed startup",
				),
			)
		}
		return err
	}
	lifecycle.Running()

	s.logger.Info(messageCodes.NewMessage(messageCodes.MSSHServiceAvailable, "SSH server running on %s", s.cfg.Listen))

	go s.handleListenSocketOnShutdown(lifecycle)
	for {
		tcpConn, err := netListener.Accept()
		if err != nil {
			// Assume listen socket closed
			break
		}
		s.wg.Add(1)
		s.logger.Debug("处理连接:::", tcpConn.RemoteAddr().String())
		// 这里 fork 子进程接管连接
		//go s.HandleConnection(tcpConn)
		go func() {
			// 主进程
			// 获取 TCP 连接的文件拷贝 f
			var f *os.File
			if f, err = tcpConn.(*net.TCPConn).File(); err != nil {
				s.logger.Error("failed to obtain connection fd")
			}
			defer f.Close()
			s.logger.Info("子命令执行")
			cmdArgs := []string{"containerssh-worker", "--config", s.configFile}
			s.logger.Info(cmdArgs)
			cmd := reexec.Command(cmdArgs...)
			cmd.Dir, _ = os.Getwd()
			cmd.Env = os.Environ()
			//cmd.Stdout = os.Stdout
			//cmd.Stderr = os.Stderr
			// Setsid 设为 true，在新的 session 中运行程序
			cmd.SysProcAttr = &syscall.SysProcAttr{
				Setsid: true,
			}
			// tcp 连接句柄传递给子进程
			cmd.ExtraFiles = []*os.File{f}
			//if err := cmd.Run(); err != nil {
			//	fmt.Printf("Error running the reexec.Command - %s\n", err)
			//}
			bs, err := cmd.CombinedOutput()
			if err != nil {
				s.logger.Error(err)
			}
			s.logger.Info(string(bs))
			s.wg.Done()
			s.logger.Info("子命令执行完毕")
		}()
	}
	lifecycle.Stopping()
	s.shuttingDown = true
	allClientsExited := make(chan struct{})
	shutdownHandlerExited := make(chan struct{}, 1)
	go s.shutdownHandlers.Shutdown(lifecycle.ShutdownContext())
	go s.disconnectClients(lifecycle, allClientsExited)
	go s.shutdownHandler(lifecycle, shutdownHandlerExited)

	s.wg.Wait()
	close(allClientsExited)
	<-shutdownHandlerExited
	// This is an expected nil return
	return nil //nolint:nilerr
}

func (s *serverImpl) handleListenSocketOnShutdown(lifecycle service.Lifecycle) {
	<-lifecycle.Context().Done()
	s.lock.Lock()
	if err := s.listenSocket.Close(); err != nil {
		s.logger.Warning(messageCodes.Wrap(err, messageCodes.ESSHListenCloseFailed, "failed to close listen socket"))
	}
	s.listenSocket = nil
	s.lock.Unlock()
}

func (s *serverImpl) disconnectClients(lifecycle service.Lifecycle, allClientsExited chan struct{}) {
	select {
	case <-allClientsExited:
		return
	case <-lifecycle.ShutdownContext().Done():
	}

	s.lock.Lock()
	for serverSocket := range s.clientSockets {
		_ = serverSocket.Close()
	}
	s.clientSockets = map[*gossh.ServerConn]bool{}
	s.lock.Unlock()
}

func (s *serverImpl) createPasswordAuthenticator(
	connectionMetadata metadata.ConnectionMetadata,
	handlerNetworkConnection NetworkConnectionHandler,
	logger log.Logger,
) func(conn gossh.ConnMetadata, password []byte) (*gossh.Permissions, metadata.ConnectionAuthenticatedMetadata, error) {
	return func(conn gossh.ConnMetadata, password []byte) (
		*gossh.Permissions,
		metadata.ConnectionAuthenticatedMetadata,
		error,
	) {
		authenticatingMetadata := connectionMetadata.StartAuthentication(string(conn.ClientVersion()), conn.User())
		authResponse, authenticatedMetadata, err := handlerNetworkConnection.OnAuthPassword(
			authenticatingMetadata,
			password,
		)

		//goland:noinspection GoNilness
		switch authResponse {
		case AuthResponseSuccess:
			s.logAuthSuccessful(logger, authenticatedMetadata, "Password")
			return &gossh.Permissions{}, authenticatedMetadata, nil
		case AuthResponseFailure:
			err = s.wrapAndLogAuthFailure(logger, authenticatingMetadata, "Password", err)
			return nil, authenticatedMetadata, err
		case AuthResponseUnavailable:
			err = s.wrapAndLogAuthUnavailable(logger, authenticatingMetadata, "Password", err)
			return nil, authenticatedMetadata, err
		}
		return nil, authenticatedMetadata, fmt.Errorf("authentication currently unavailable")
	}
}

func (s *serverImpl) wrapAndLogAuthUnavailable(
	logger log.Logger,
	conn metadata.ConnectionAuthPendingMetadata,
	authMethod string,
	err error,
) error {
	err = messageCodes.WrapUser(
		err,
		messageCodes.ESSHAuthUnavailable,
		"Authentication is currently unavailable, please try a different authentication method or try again later.",
		"%s authentication for user %s currently unavailable.",
		authMethod,
		conn.Username,
	).
		Label("username", conn.Username).
		Label("method", strings.ToLower(authMethod)).
		Label("reason", err.Error())
	logger.Info(err)
	return err
}

func (s *serverImpl) wrapAndLogAuthFailure(
	logger log.Logger,
	conn metadata.ConnectionAuthPendingMetadata,
	authMethod string,
	err error,
) error {
	if err == nil {
		err = messageCodes.UserMessage(
			messageCodes.ESSHAuthFailed,
			"Authentication failed.",
			"%s authentication for user %s failed.",
			authMethod,
			conn.Username,
		).
			Label("username", conn.Username).
			Label("method", strings.ToLower(authMethod))
		logger.Info(err)
	} else {
		err = messageCodes.WrapUser(
			err,
			messageCodes.ESSHAuthFailed,
			"Authentication failed.",
			"%s authentication for user %s failed.",
			authMethod,
			conn.Username,
		).
			Label("username", conn.Username).
			Label("method", strings.ToLower(authMethod)).
			Label("reason", err.Error())
		logger.Info(err)
	}
	return err
}

func (s *serverImpl) logAuthSuccessful(
	logger log.Logger,
	conn metadata.ConnectionAuthenticatedMetadata,
	authMethod string,
) {
	err := messageCodes.UserMessage(
		messageCodes.ESSHAuthSuccessful,
		"Authentication successful.",
		"%s authentication for user %s successful.",
		authMethod,
		conn.Username,
	).Label("username", conn.Username).Label("method", strings.ToLower(authMethod))
	logger.Info(err)
}

func (s *serverImpl) createPubKeyAuthenticator(
	connectionMetadata metadata.ConnectionMetadata,
	handlerNetworkConnection NetworkConnectionHandler,
	logger log.Logger,
) func(conn gossh.ConnMetadata, pubKey gossh.PublicKey) (
	*gossh.Permissions,
	metadata.ConnectionAuthenticatedMetadata,
	error,
) {
	return func(conn gossh.ConnMetadata, pubKey gossh.PublicKey) (
		*gossh.Permissions,
		metadata.ConnectionAuthenticatedMetadata,
		error,
	) {
		authenticatingMetadata := connectionMetadata.StartAuthentication(string(conn.ClientVersion()), conn.User())
		authorizedKey := strings.TrimSpace(string(gossh.MarshalAuthorizedKey(pubKey)))
		authResponse, authenticatedMetadata, err := handlerNetworkConnection.OnAuthPubKey(
			authenticatingMetadata,
			auth.PublicKey{PublicKey: authorizedKey},
		)
		//goland:noinspection GoNilness
		switch authResponse {
		case AuthResponseSuccess:
			s.logAuthSuccessful(logger, authenticatedMetadata, "Public key")
			return &gossh.Permissions{}, authenticatedMetadata, nil
		case AuthResponseFailure:
			err = s.wrapAndLogAuthFailure(logger, authenticatingMetadata, "Public key", err)
			return nil, authenticatedMetadata, err
		case AuthResponseUnavailable:
			err = s.wrapAndLogAuthUnavailable(logger, authenticatingMetadata, "Public key", err)
			return nil, authenticatedMetadata, err
		}
		// This should never happen
		return nil, authenticatedMetadata, fmt.Errorf("authentication currently unavailable")
	}
}

func (s *serverImpl) createKeyboardInteractiveHandler(
	connectionMetadata metadata.ConnectionMetadata,
	handlerNetworkConnection *networkConnectionWrapper,
	logger log.Logger,
) func(conn gossh.ConnMetadata, challenge gossh.KeyboardInteractiveChallenge) (
	*gossh.Permissions,
	metadata.ConnectionAuthenticatedMetadata,
	error,
) {
	return func(
		conn gossh.ConnMetadata,
		challenge gossh.KeyboardInteractiveChallenge,
	) (*gossh.Permissions, metadata.ConnectionAuthenticatedMetadata, error) {
		authenticatingMetadata := connectionMetadata.StartAuthentication(string(conn.ClientVersion()), conn.User())
		challengeWrapper := func(
			instruction string,
			questions KeyboardInteractiveQuestions,
		) (answers KeyboardInteractiveAnswers, err error) {
			if answers.answers == nil {
				answers.answers = map[string]string{}
			}
			var q []string
			var echos []bool
			for _, question := range questions {
				q = append(q, question.Question)
				echos = append(echos, question.EchoResponse)
			}

			// user, instruction string, questions []string, echos []bool
			answerList, err := challenge(conn.User(), instruction, q, echos)
			for index, rawAnswer := range answerList {
				question := questions[index]
				answers.answers[question.getID()] = rawAnswer
			}
			return answers, err
		}
		authResponse, authenticatedMetadata, err := handlerNetworkConnection.OnAuthKeyboardInteractive(
			authenticatingMetadata,
			challengeWrapper,
		)
		//goland:noinspection GoNilness
		switch authResponse {
		case AuthResponseSuccess:
			s.logAuthSuccessful(logger, authenticatedMetadata, "Keyboard-interactive")
			return &gossh.Permissions{}, authenticatedMetadata, nil
		case AuthResponseFailure:
			err = s.wrapAndLogAuthFailure(logger, authenticatingMetadata, "Keyboard-interactive", err)
			return nil, authenticatedMetadata, err
		case AuthResponseUnavailable:
			err = s.wrapAndLogAuthUnavailable(logger, authenticatingMetadata, "Keyboard-interactive", err)
			return nil, authenticatedMetadata, err
		}
		return nil, authenticatedMetadata, fmt.Errorf("authentication currently unavailable")
	}
}

func (s *serverImpl) createConfiguration(
	meta metadata.ConnectionMetadata,
	handlerNetworkConnection *networkConnectionWrapper,
	logger log.Logger,
	ctx ssh.Context,
) *gossh.ServerConfig {
	passwordCallback, pubkeyCallback, keyboardInteractiveCallback, gssConfig := s.createAuthenticators(
		meta,
		handlerNetworkConnection,
		logger,
		ctx,
	)

	serverConfig := &gossh.ServerConfig{
		Config: gossh.Config{
			KeyExchanges: s.cfg.KexAlgorithms.StringList(),
			Ciphers:      s.cfg.Ciphers.StringList(),
			MACs:         s.cfg.MACs.StringList(),
		},
		NoClientAuth:                false,
		MaxAuthTries:                6,
		PasswordCallback:            passwordCallback,
		PublicKeyCallback:           pubkeyCallback,
		KeyboardInteractiveCallback: keyboardInteractiveCallback,
		GSSAPIWithMICConfig:         gssConfig,
		ServerVersion:               s.cfg.ServerVersion.String(),
		BannerCallback:              func(conn gossh.ConnMetadata) string { return s.cfg.Banner },
	}
	for _, key := range s.hostKeys {
		serverConfig.AddHostKey(key)
	}
	return serverConfig
}

func (s *serverImpl) createAuthenticators(
	meta metadata.ConnectionMetadata,
	handlerNetworkConnection *networkConnectionWrapper,
	logger log.Logger,
	ctx ssh.Context,
) (
	func(conn gossh.ConnMetadata, password []byte) (*gossh.Permissions, error),
	func(conn gossh.ConnMetadata, key gossh.PublicKey) (*gossh.Permissions, error),
	func(conn gossh.ConnMetadata, challenge gossh.KeyboardInteractiveChallenge) (*gossh.Permissions, error),
	*gossh.GSSAPIWithMICConfig,
) {

	passwordCallback := s.createPasswordCallback(meta, handlerNetworkConnection, logger, ctx)
	pubkeyCallback := s.createPubKeyCallback(meta, handlerNetworkConnection, logger, ctx)
	keyboardInteractiveCallback := s.createKeyboardInteractiveCallback(meta, handlerNetworkConnection, logger, ctx)
	gssConfig := s.createGSSAPIConfig(meta, handlerNetworkConnection, logger)
	return passwordCallback, pubkeyCallback, keyboardInteractiveCallback, gssConfig
}

func (s *serverImpl) createGSSAPIConfig(
	connectionMetadata metadata.ConnectionMetadata,
	handlerNetworkConnection *networkConnectionWrapper,
	logger log.Logger,
) *gossh.GSSAPIWithMICConfig {
	var gssConfig *gossh.GSSAPIWithMICConfig

	gssServer := handlerNetworkConnection.OnAuthGSSAPI(connectionMetadata)
	if gssServer != nil {
		gssConfig = &gossh.GSSAPIWithMICConfig{
			AllowLogin: func(conn gossh.ConnMetadata, srcName string) (*gossh.Permissions, error) {
				if !gssServer.Success() {
					if gssServer.Error() == nil {
						return nil, messageCodes.NewMessage(
							messageCodes.ESSHAuthFailed,
							"Authentication failed",
						)
					}
					return nil, gssServer.Error()
				}

				authenticating := connectionMetadata.StartAuthentication(string(conn.ClientVersion()), conn.User())
				authenticated, err := gssServer.AllowLogin(conn.User(), authenticating)
				if err != nil {
					return nil, s.wrapAndLogAuthFailure(logger, authenticating, "GSSAPI", err)
				}
				handlerNetworkConnection.authenticatedMetadata = authenticated
				s.logAuthSuccessful(logger, authenticated, "GSSAPI")
				sshConnectionHandler, _, err := handlerNetworkConnection.OnHandshakeSuccess(
					authenticated,
					nil,
				)
				if err != nil {
					err = messageCodes.WrapUser(
						err,
						messageCodes.ESSHBackendRejected,
						"Authentication currently unavailable, please try again later.",
						"The backend has rejected the user after successful authentication.",
					)
					logger.Error(err)
					return nil, err
				}
				handlerNetworkConnection.sshConnectionHandler = sshConnectionHandler
				return &gossh.Permissions{}, nil
			},
			Server: gssServer,
		}
	}
	return gssConfig
}

func (s *serverImpl) createKeyboardInteractiveCallback(
	connectionMetadata metadata.ConnectionMetadata,
	handlerNetworkConnection *networkConnectionWrapper,
	logger log.Logger,
	ctx ssh.Context,
) func(conn gossh.ConnMetadata, challenge gossh.KeyboardInteractiveChallenge) (*gossh.Permissions, error) {
	keyboardInteractiveHandler := s.createKeyboardInteractiveHandler(
		connectionMetadata,
		handlerNetworkConnection,
		logger,
	)
	keyboardInteractiveCallback := func(
		conn gossh.ConnMetadata,
		challenge gossh.KeyboardInteractiveChallenge,
	) (*gossh.Permissions, error) {
		permissions, authenticatedMetadata, err := keyboardInteractiveHandler(conn, challenge)
		if err != nil {
			return permissions, err
		}
		// HACK: check HACKS.md "OnHandshakeSuccess conformanceTestHandler"
		sshConnectionHandler, _, err := handlerNetworkConnection.OnHandshakeSuccess(
			authenticatedMetadata,
			ctx,
		)
		if err != nil {
			err = messageCodes.WrapUser(
				err,
				messageCodes.ESSHBackendRejected,
				"Authentication currently unavailable, please try again later.",
				"The backend has rejected the user after successful authentication.",
			)
			logger.Error(err)
			return permissions, err
		}
		handlerNetworkConnection.authenticatedMetadata = authenticatedMetadata
		handlerNetworkConnection.sshConnectionHandler = sshConnectionHandler
		return permissions, err
	}
	return keyboardInteractiveCallback
}

func (s *serverImpl) createPubKeyCallback(
	meta metadata.ConnectionMetadata,
	handlerNetworkConnection *networkConnectionWrapper,
	logger log.Logger,
	ctx ssh.Context,
) func(conn gossh.ConnMetadata, key gossh.PublicKey) (*gossh.Permissions, error) {
	pubKeyHandler := s.createPubKeyAuthenticator(meta, handlerNetworkConnection, logger)
	pubkeyCallback := func(conn gossh.ConnMetadata, key gossh.PublicKey) (*gossh.Permissions, error) {
		permissions, authenticatedMetadata, err := pubKeyHandler(conn, key)
		if err != nil {
			return permissions, err
		}
		// HACK: check HACKS.md "OnHandshakeSuccess conformanceTestHandler"
		sshConnectionHandler, _, err := handlerNetworkConnection.OnHandshakeSuccess(
			authenticatedMetadata,
			ctx,
		)
		if err != nil {
			err = messageCodes.WrapUser(
				err,
				messageCodes.ESSHBackendRejected,
				"Authentication currently unavailable, please try again later.",
				"The backend has rejected the user after successful authentication.",
			)
			logger.Error(err)
			return permissions, err
		}
		handlerNetworkConnection.authenticatedMetadata = authenticatedMetadata
		handlerNetworkConnection.sshConnectionHandler = sshConnectionHandler
		return permissions, err
	}
	return pubkeyCallback
}

func (s *serverImpl) createPasswordCallback(
	meta metadata.ConnectionMetadata,
	handlerNetworkConnection *networkConnectionWrapper,
	logger log.Logger,
	ctx ssh.Context,
) func(conn gossh.ConnMetadata, password []byte) (*gossh.Permissions, error) {
	passwordHandler := s.createPasswordAuthenticator(meta, handlerNetworkConnection, logger)
	passwordCallback := func(conn gossh.ConnMetadata, password []byte) (*gossh.Permissions, error) {
		permissions, authenticatedMetadata, err := passwordHandler(conn, password)
		if err != nil {
			return permissions, err
		}
		// HACK: check HACKS.md "OnHandshakeSuccess conformanceTestHandler"
		sshConnectionHandler, _, err := handlerNetworkConnection.OnHandshakeSuccess(
			authenticatedMetadata,
			ctx,
		)
		if err != nil {
			err = messageCodes.WrapUser(
				err,
				messageCodes.ESSHBackendRejected,
				"Authentication currently unavailable, please try again later.",
				"The backend has rejected the user after successful authentication.",
			)
			logger.Error(err)
			return permissions, err
		}
		handlerNetworkConnection.authenticatedMetadata = authenticatedMetadata
		handlerNetworkConnection.sshConnectionHandler = sshConnectionHandler
		return permissions, err
	}
	return passwordCallback
}

func (s *serverImpl) HandleConnection(conn net.Conn) {
	addr := conn.RemoteAddr().(*net.TCPAddr)
	connectionID := GenerateConnectionID()
	logger := s.logger.
		WithLabel("remoteAddr", addr.IP.String()).
		WithLabel("connectionId", connectionID)
	connectionMeta := metadata.ConnectionMetadata{
		RemoteAddress: metadata.RemoteAddress(*addr),
		ConnectionID:  connectionID,
		Metadata:      map[string]metadata.Value{},
		Environment:   map[string]metadata.Value{},
		Files:         map[string]metadata.BinaryValue{},
	}

	handlerNetworkConnection, connectionMeta, err := s.handler.OnNetworkConnection(connectionMeta)
	if err != nil {
		logger.Info(err)
		_ = conn.Close()
		s.wg.Done()
		return
	}
	shutdownHandlerID := fmt.Sprintf("network-%s", connectionID)
	s.shutdownHandlers.Register(shutdownHandlerID, handlerNetworkConnection)

	logger.Debug(
		messageCodes.NewMessage(
			messageCodes.MSSHConnected, "Client connected",
		),
	)

	// 初始化 ssh.Conetxt ,用来传递连接上下文，ctx 通过 OnHandshakeSuccess 方法进行设置
	ctx, _ := newContext(s)

	ctx.SetValue(ContextKeyConnectionID, connectionID)
	// HACK: check HACKS.md "OnHandshakeSuccess conformanceTestHandler"
	wrapper := networkConnectionWrapper{
		NetworkConnectionHandler: handlerNetworkConnection,
		ctx:                      ctx,
	}

	// 初始化当前连接的配置（包括身份验证等）
	sshConn, channels, globalRequests, err := gossh.NewServerConn(
		conn,
		s.createConfiguration(connectionMeta, &wrapper, logger, ctx),
	)

	if err != nil {
		logger.Info(messageCodes.Wrap(err, messageCodes.ESSHHandshakeFailed, "SSH handshake failed"))
		handlerNetworkConnection.OnHandshakeFailed(connectionMeta, err)
		s.shutdownHandlers.Unregister(shutdownHandlerID)
		logger.Debug(messageCodes.NewMessage(messageCodes.MSSHDisconnected, "Client disconnected"))
		handlerNetworkConnection.OnDisconnect()
		logger.Debug("客户端关闭")
		_ = conn.Close()
		s.wg.Done()
		return
	}

	authenticatedMetadata := wrapper.authenticatedMetadata
	logger = logger.WithLabel("username", sshConn.User())
	logger.Debug(authenticatedMetadata.Username, wrapper.authenticatedMetadata.RemoteAddress.String())
	logger.Debug(messageCodes.NewMessage(messageCodes.MSSHHandshakeSuccessful, "SSH handshake successful xxxsshd 888---"))
	if s.clientSockets == nil {
		s.clientSockets = map[*gossh.ServerConn]bool{}
	}

	if s.connMap == nil {
		s.connMap = map[string]connection{}
	}

	s.lock.Lock()
	s.clientSockets[sshConn] = true
	s.connMap[connectionID] = connection{
		sshConn:         sshConn,
		reverseForwards: make(map[string]*protocol.ForwardCtx),
	}

	applyConnMetadata(ctx, sshConn)

	sshShutdownHandlerID := fmt.Sprintf("ssh-%s", connectionID)
	s.lock.Unlock()
	logger.Info("登录成功")
	if s.cfg.ClientAliveInterval > 0 {
		go func() {
			missedAlives := 0
			for {
				time.Sleep(s.cfg.ClientAliveInterval)

				_, _, err := sshConn.SendRequest("keepalive@openssh.com", true, []byte{})

				if err != nil {
					missedAlives++

					logger.Debug(
						messageCodes.Wrap(
							err,
							messageCodes.ESSHKeepAliveFailed,
							"Keepalive error",
						),
					)
					if missedAlives >= s.cfg.ClientAliveCountMax {
						s.logger.Error(fmt.Sprintf("connId: %s   心跳失败 %d 次", connectionID, missedAlives))
						time.Sleep(15 * time.Second)
						_ = sshConn.Close()
						break
					}
					continue
				}
				missedAlives = 0
			}
		}()
	}

	go func() {
		err := sshConn.Wait()
		if err != nil {
			logger.Error(err)
		}
		logger.Debug(messageCodes.NewMessage(messageCodes.MSSHDisconnected, "Client disconnected 000"))
		s.shutdownHandlers.Unregister(shutdownHandlerID)
		s.shutdownHandlers.Unregister(sshShutdownHandlerID)
		handlerNetworkConnection.OnDisconnect()
		s.wg.Done()
	}()
	// HACK: check HACKS.md "OnHandshakeSuccess conformanceTestHandler"
	handlerSSHConnection := wrapper.sshConnectionHandler
	s.shutdownHandlers.Register(sshShutdownHandlerID, handlerSSHConnection)

	go s.handleChannels(authenticatedMetadata, channels, handlerSSHConnection, logger, ctx)
	go s.handleGlobalRequests(authenticatedMetadata, globalRequests, handlerSSHConnection, logger, ctx)
}

func (s *serverImpl) handleKeepAliveRequest(req *gossh.Request, logger log.Logger) {
	if req.WantReply {
		if err := req.Reply(false, []byte{}); err != nil {
			logger.Debug(
				messageCodes.Wrap(
					err,
					messageCodes.ESSHReplyFailed,
					"failed to send reply to global request type %s",
					req.Type,
				),
			)
		}
	}
}

//nolint:dupl
func (s *serverImpl) handleGlobalRequest(authenticatedMetadata metadata.ConnectionAuthenticatedMetadata, requestID uint64, connection SSHConnectionHandler, req *gossh.Request, logger log.Logger, ctx ssh.Context) {
	reply := s.createReply(req, logger)
	payload, err := s.unmarshalGlobalRequestPayload(req)
	if payload == nil {
		connection.OnUnsupportedGlobalRequest(requestID, req.Type, req.Payload)
		reply(false, fmt.Sprintf("unsupported global request type: %s", req.Type), nil)
		return
	}
	if err != nil {
		logger.Debug(
			messageCodes.Wrap(
				err,
				messageCodes.ESSHDecodeFailed,
				"failed to unmarshal %s request payload",
				req.Type,
			),
		)
		connection.OnFailedDecodeGlobalRequest(requestID, req.Type, req.Payload, err)
		reply(false, "failed to unmarshal payload", nil)
		return
	}

	logger.Debug(
		messageCodes.NewMessage(
			messageCodes.MSSHGlobalRequest,
			"%s global request from client",
			req.Type,
		).Label("RequestType", req.Type),
	)
	if err := s.handleDecodedGlobalRequest(
		authenticatedMetadata,
		requestID,
		ssh2.RequestType(req.Type),
		payload,
		connection,
	); err != nil {
		logger.Debug(
			messageCodes.NewMessage(
				messageCodes.MSSHGlobalRequestFailed,
				"%s global request from client failed",
				req.Type,
			).Label("RequestType", req.Type),
		)
		reply(false, err.Error(), err)
		return
	}
	logger.Debug(
		messageCodes.NewMessage(
			messageCodes.MSSHGlobalRequestSuccessful,
			"%s global request from client successful",
			req.Type,
		).Label("RequestType", req.Type),
	)
	reply(true, "", nil)
}

func (s *serverImpl) handleDecodedGlobalRequest(
	authenticatedMetadata metadata.ConnectionAuthenticatedMetadata,
	requestID uint64,
	requestType ssh2.RequestType,
	payload interface{},
	connection SSHConnectionHandler,
) error {
	switch requestType {
	case ssh2.RequestTypeReverseForward:
		return s.onForwardTCPIP(authenticatedMetadata, requestID, payload, connection)
	case ssh2.RequestTypeCancelReverseForward:
		return s.onCancelForward(authenticatedMetadata, requestID, payload, connection)
	case ssh2.RequestTypeStreamLocalForward:
		return s.onForwardStreamLocal(authenticatedMetadata, requestID, payload, connection)
	case ssh2.RequestTypeCancelStreamLocalForward:
		return s.onCancelForwardStreamLocal(authenticatedMetadata, requestID, payload, connection)
	}
	return nil
}

func (s *serverImpl) handleUnknownGlobalRequest(req *gossh.Request, requestID uint64, connection SSHConnectionHandler, logger log.Logger) {
	logger.Debug(
		messageCodes.NewMessage(messageCodes.ESSHUnsupportedGlobalRequest, "Unsupported global request").Label(
			"type",
			req.Type,
		),
	)

	connection.OnUnsupportedGlobalRequest(requestID, req.Type, req.Payload)
	if req.WantReply {
		if err := req.Reply(false, []byte("request type not supported")); err != nil {
			logger.Debug(
				messageCodes.Wrap(
					err,
					messageCodes.ESSHReplyFailed,
					"failed to send reply to global request type %s",
					req.Type,
				),
			)
		}
	}
}

func (s *serverImpl) handleGlobalRequests(
	authenticatedMetadata metadata.ConnectionAuthenticatedMetadata,
	requests <-chan *gossh.Request,
	connection SSHConnectionHandler,
	logger log.Logger,
	ctx ssh.Context,
) {
	for {
		request, ok := <-requests
		if !ok {
			break
		}
		requestID := s.nextGlobalRequestID
		s.nextGlobalRequestID++

		// Keepalive gets a fast-track and is not logged because we'll get a lot of those
		switch request.Type {
		case "keepalive@openssh.com":
			s.handleKeepAliveRequest(request, logger)
		default:
			logger.Debug("Handling global request %s", request.Type)
			s.handleGlobalRequest(authenticatedMetadata, requestID, connection, request, logger, ctx)
		}
	}
}

func (s *serverImpl) handleChannels(
	authenticatedMetadata metadata.ConnectionAuthenticatedMetadata,
	channels <-chan gossh.NewChannel,
	connection SSHConnectionHandler,
	logger log.Logger,
	ctx ssh.Context,
) {
	for {
		newChannel, ok := <-channels
		if !ok {
			break
		}
		s.lock.Lock()
		channelID := s.nextChannelID
		s.nextChannelID++
		s.lock.Unlock()
		logger = logger.WithLabel("channelId", channelID)
		switch newChannel.ChannelType() {
		case ChannelTypeSession:
			go s.handleSessionChannel(authenticatedMetadata.Channel(channelID), newChannel, connection, logger, ctx)
		case ChannelTypeDirectTCPIP:
			go s.handleDirectForwardingChannel(authenticatedMetadata.Channel(channelID), newChannel, connection, logger, ctx)
		case ChannelTypeDirectStreamLocal:
			go s.handleDirectStreamLocalChannel(authenticatedMetadata.Channel(channelID), newChannel, connection, logger, ctx)
		default:
			logger.Debug(
				messageCodes.NewMessage(
					messageCodes.ESSHUnsupportedChannelType,
					"Unsupported channel type requested",
				).Label("type", newChannel.ChannelType()),
			)
			connection.OnUnsupportedChannel(channelID, newChannel.ChannelType(), newChannel.ExtraData())
			if err := newChannel.Reject(gossh.UnknownChannelType, "unsupported channel type"); err != nil {
				logger.Debug("failed to send channel rejection for channel type %s", newChannel.ChannelType())
			}
			continue
		}
	}
}

func (s *serverImpl) handleSessionChannel(
	channelMetadata metadata.ChannelMetadata,
	newChannel gossh.NewChannel,
	connection SSHConnectionHandler,
	logger log.Logger,
	ctx ssh.Context,
) {
	channelCallbacks := &channelWrapper{
		logger: logger,
		lock:   &sync.Mutex{},
		ctx:    ctx,
	}
	handlerChannel, rejection := connection.OnSessionChannel(channelMetadata, newChannel.ExtraData(), channelCallbacks)
	if rejection != nil {
		logger.Debug(
			messageCodes.Wrap(
				rejection,
				messageCodes.MSSHNewChannelRejected,
				"New SSH channel rejected",
			).Label("type", newChannel.ChannelType()),
		)

		if err := newChannel.Reject(rejection.Reason(), rejection.UserMessage()); err != nil {
			logger.Debug(messageCodes.Wrap(err, messageCodes.ESSHReplyFailed, "Failed to send reply to channel request"))
		}
		return
	}
	shutdownHandlerID := fmt.Sprintf(
		"session-%s-%d",
		channelMetadata.Connection.ConnectionID,
		channelMetadata.ChannelID,
	)
	s.shutdownHandlers.Register(shutdownHandlerID, handlerChannel)
	channel, requests, err := newChannel.Accept()
	if err != nil {
		logger.Debug(messageCodes.Wrap(err, messageCodes.ESSHReplyFailed, "failed to accept session channel"))
		s.shutdownHandlers.Unregister(shutdownHandlerID)
		return
	}
	logger.Debug(messageCodes.NewMessage(messageCodes.MSSHNewChannel, "New SSH channel").Label("type", newChannel.ChannelType()))
	channelCallbacks.channel = channel
	nextRequestID := uint64(0)
	for {
		request, ok := <-requests
		if !ok {
			s.shutdownHandlers.Unregister(shutdownHandlerID)
			channelCallbacks.onClose()
			handlerChannel.OnClose()
			break
		}
		s.logger.Debug("requestrequestrequestrequest", request.Type, request.WantReply, ok)
		requestID := nextRequestID
		nextRequestID++
		s.handleChannelRequest(channelMetadata, requestID, request, handlerChannel, logger)
	}
}

func serveConnection(log log.Logger, dst io.WriteCloser, src io.ReadCloser) {
	_, err := io.Copy(dst, src)
	if err != nil && !errors.Is(err, io.EOF) {
		log.Warning("3333 Connection error", err)
	}
	_ = dst.Close()
	_ = src.Close()
}

func (s *serverImpl) handleDirectForwardingChannel(
	channelMetadata metadata.ChannelMetadata,
	newChannel gossh.NewChannel,
	connection SSHConnectionHandler,
	logger log.Logger,
	ctx ssh.Context,
) {
	var payload ssh2.ForwardTCPChannelOpenPayload
	err := gossh.Unmarshal(newChannel.ExtraData(), &payload)
	if err != nil {
		logger.Warning(
			messageCodes.Wrap(
				err,
				messageCodes.MSSHNewChannelRejected,
				"Failed to decode new forwarding channel payload",
			),
		)
		return
	}

	handlerChannel, rejection := connection.OnTCPForwardChannel(channelMetadata.ChannelID, payload.ConnectedAddress, payload.ConnectedPort, payload.OriginatorAddress, payload.OriginatorPort)
	if rejection != nil {
		logger.Debug(
			messageCodes.Wrap(
				rejection,
				messageCodes.MSSHNewChannelRejected,
				"New forwarding channel rejected",
			).Label("type", newChannel.ChannelType()),
		)

		if err := newChannel.Reject(rejection.Reason(), rejection.UserMessage()); err != nil {
			logger.Debug(messageCodes.Wrap(err, messageCodes.ESSHReplyFailed, "Failed to send reply to channel request"))
		}
		return
	}
	shutdownHandlerID := fmt.Sprintf("direct-tcpip-%s-%d", channelMetadata.Connection.ConnectionID, channelMetadata.ChannelID)
	s.shutdownHandlers.Register(shutdownHandlerID, &shutdownCloser{
		closer: handlerChannel,
	})
	channel, requests, err := newChannel.Accept()
	if err != nil {
		logger.Debug(messageCodes.Wrap(err, messageCodes.ESSHReplyFailed, "failed to accept forwarding channel"))
		s.shutdownHandlers.Unregister(shutdownHandlerID)
		return
	}
	logger.Debug(messageCodes.NewMessage(messageCodes.MSSHNewChannel, "New SSH channel").Label("type", newChannel.ChannelType()))
	go serveConnection(logger, handlerChannel, channel)
	go serveConnection(logger, channel, handlerChannel)
	for {
		request, ok := <-requests
		if !ok {
			s.shutdownHandlers.Unregister(shutdownHandlerID)
			_ = handlerChannel.Close()
			break
		}
		if request.WantReply {
			_ = request.Reply(false, []byte{})
		}
	}
}

func (s *serverImpl) handleDirectStreamLocalChannel(
	channelMetadata metadata.ChannelMetadata,
	newChannel gossh.NewChannel,
	connection SSHConnectionHandler,
	logger log.Logger,
	ctx ssh.Context,
) {
	var payload ssh2.DirectStreamLocalChannelOpenPayload
	err := gossh.Unmarshal(newChannel.ExtraData(), &payload)
	if err != nil {
		logger.Warning(
			messageCodes.Wrap(
				err,
				messageCodes.MSSHNewChannelRejected,
				"Failed to decode new forwarding channel payload",
			),
		)
		return
	}

	handlerChannel, rejection := connection.OnDirectStreamLocal(channelMetadata.ChannelID, payload.SocketPath)
	if rejection != nil {
		logger.Debug(
			messageCodes.Wrap(
				rejection,
				messageCodes.MSSHNewChannelRejected,
				"New streamlocal forwarding channel rejected",
			).Label("type", newChannel.ChannelType()),
		)

		if err := newChannel.Reject(rejection.Reason(), rejection.UserMessage()); err != nil {
			logger.Debug(messageCodes.Wrap(err, messageCodes.ESSHReplyFailed, "Failed to send reply to channel request"))
		}
		return
	}
	shutdownHandlerID := fmt.Sprintf("direct-tcpip-%s-%d", channelMetadata.Connection.ConnectionID, channelMetadata.ChannelID)
	s.shutdownHandlers.Register(shutdownHandlerID, &shutdownCloser{
		closer: handlerChannel,
	})
	channel, requests, err := newChannel.Accept()
	if err != nil {
		logger.Debug(messageCodes.Wrap(err, messageCodes.ESSHReplyFailed, "failed to streamlocal forwarding channel"))
		s.shutdownHandlers.Unregister(shutdownHandlerID)
		return
	}
	logger.Debug(messageCodes.NewMessage(messageCodes.MSSHNewChannel, "New SSH channel").Label("type", newChannel.ChannelType()))
	go serveConnection(logger, handlerChannel, channel)
	go serveConnection(logger, channel, handlerChannel)
	for {
		request, ok := <-requests
		if !ok {
			s.shutdownHandlers.Unregister(shutdownHandlerID)
			_ = handlerChannel.Close()
			break
		}
		if request.WantReply {
			_ = request.Reply(false, []byte{})
		}
	}
}

func (s *serverImpl) unmarshalEnv(request *gossh.Request) (payload ssh2.EnvRequestPayload, err error) {
	return payload, gossh.Unmarshal(request.Payload, &payload)
}

func (s *serverImpl) unmarshalPty(request *gossh.Request) (payload ssh2.PtyRequestPayload, err error) {
	return payload, gossh.Unmarshal(request.Payload, &payload)
}

func (s *serverImpl) unmarshalShell(request *gossh.Request) (payload ssh2.ShellRequestPayload, err error) {
	if len(request.Payload) != 0 {
		err = gossh.Unmarshal(request.Payload, &payload)
	}
	return payload, err
}

func (s *serverImpl) unmarshalExec(request *gossh.Request) (payload ssh2.ExecRequestPayload, err error) {
	return payload, gossh.Unmarshal(request.Payload, &payload)
}

func (s *serverImpl) unmarshalSubsystem(request *gossh.Request) (payload ssh2.SubsystemRequestPayload, err error) {
	return payload, gossh.Unmarshal(request.Payload, &payload)
}

func (s *serverImpl) unmarshalWindow(request *gossh.Request) (payload ssh2.WindowRequestPayload, err error) {
	return payload, gossh.Unmarshal(request.Payload, &payload)
}

func (s *serverImpl) unmarshalSignal(request *gossh.Request) (payload ssh2.SignalRequestPayload, err error) {
	return payload, gossh.Unmarshal(request.Payload, &payload)
}

func (s *serverImpl) unmarshalTCPIPForward(request *gossh.Request) (payload ssh2.ForwardTCPIPRequestPayload, err error) {
	return payload, gossh.Unmarshal(request.Payload, &payload)
}

func (s *serverImpl) unmarshalStreamLocalForward(request *gossh.Request) (payload ssh2.StreamLocalForwardRequestPayload, err error) {
	s.logger.Debug("Unmarshalling streamlocal: %+v", request.Payload)
	return payload, gossh.Unmarshal(request.Payload, &payload)
}

func (s *serverImpl) unmarshalX11(request *gossh.Request) (payload ssh2.X11RequestPayload, err error) {
	return payload, gossh.Unmarshal(request.Payload, &payload)
}

func (s *serverImpl) unmarshalChannelRequestPayload(request *gossh.Request) (payload interface{}, err error) {
	switch ssh2.RequestType(request.Type) {
	case ssh2.RequestTypeEnv:
		return s.unmarshalEnv(request)
	case ssh2.RequestTypePty:
		return s.unmarshalPty(request)
	case ssh2.RequestTypeShell:
		return s.unmarshalShell(request)
	case ssh2.RequestTypeExec:
		return s.unmarshalExec(request)
	case ssh2.RequestTypeSubsystem:
		return s.unmarshalSubsystem(request)
	case ssh2.RequestTypeWindow:
		return s.unmarshalWindow(request)
	case ssh2.RequestTypeSignal:
		return s.unmarshalSignal(request)
	case ssh2.RequestTypeX11:
		return s.unmarshalX11(request)
	default:
		return nil, nil
	}
}

func (s *serverImpl) unmarshalGlobalRequestPayload(request *gossh.Request) (payload interface{}, err error) {
	switch ssh2.RequestType(request.Type) {
	case ssh2.RequestTypeReverseForward:
		return s.unmarshalTCPIPForward(request)
	case ssh2.RequestTypeCancelReverseForward:
		return s.unmarshalTCPIPForward(request)
	case ssh2.RequestTypeStreamLocalForward:
		return s.unmarshalStreamLocalForward(request)
	case ssh2.RequestTypeCancelStreamLocalForward:
		return s.unmarshalStreamLocalForward(request)
	default:
		return nil, nil
	}
}

//nolint:dupl
func (s *serverImpl) handleChannelRequest(
	channelMetadata metadata.ChannelMetadata,
	requestID uint64,
	request *gossh.Request,
	sessionChannel SessionChannelHandler,
	logger log.Logger,
) {
	logger.Debug("handleChannelRequesthandleChannelRequest", request.Type)
	reply := s.createReply(request, logger)
	payload, err := s.unmarshalChannelRequestPayload(request)
	if payload == nil {
		sessionChannel.OnUnsupportedChannelRequest(requestID, request.Type, request.Payload)
		reply(false, fmt.Sprintf("unsupported request type: %s", request.Type), nil)
		return
	}
	if err != nil {
		logger.Debug(
			messageCodes.Wrap(
				err,
				messageCodes.ESSHDecodeFailed,
				"failed to unmarshal %s request payload",
				request.Type,
			),
		)
		sessionChannel.OnFailedDecodeChannelRequest(requestID, request.Type, request.Payload, err)
		reply(false, "failed to unmarshal payload", nil)
		return
	}
	logger.Debug(
		messageCodes.NewMessage(
			messageCodes.MSSHChannelRequest,
			"%s channel request from client",
			request.Type,
		).Label("RequestType", request.Type),
	)
	if err := s.handleDecodedChannelRequest(
		channelMetadata,
		requestID,
		ssh2.RequestType(request.Type),
		payload,
		sessionChannel,
	); err != nil {
		logger.Debug(
			messageCodes.NewMessage(
				messageCodes.MSSHChannelRequestFailed,
				"%s channel request from client failed",
				request.Type,
				err,
			).Label("RequestType", request.Type),
		)
		reply(false, err.Error(), err)
		return
	}
	logger.Debug(
		messageCodes.NewMessage(
			messageCodes.MSSHChannelRequestSuccessful,
			"%s channel request from client successful",
			request.Type,
		).Label("RequestType", request.Type),
	)
	reply(true, "", nil)
}

func (s *serverImpl) createReply(request *gossh.Request, logger log.Logger) func(
	success bool,
	message string,
	reason error,
) {
	reply := func(success bool, message string, reason error) {
		if request.WantReply {
			if err := request.Reply(
				success,
				[]byte(message),
			); err != nil && err != io.EOF {
				logger.Debug(
					messageCodes.Wrap(
						err,
						messageCodes.ESSHReplyFailed,
						"Failed to send reply to client",
					),
				)
			}
		}
	}
	return reply
}

func (s *serverImpl) handleDecodedChannelRequest(
	channelMetadata metadata.ChannelMetadata,
	requestID uint64,
	requestType ssh2.RequestType,
	payload interface{},
	sessionChannel SessionChannelHandler,
) error {
	s.logger.Debug("requestTyperequestTyperequestType", requestType)
	switch requestType {
	case ssh2.RequestTypeEnv:
		return s.onEnvRequest(requestID, sessionChannel, payload)
	case ssh2.RequestTypePty:
		return s.onPtyRequest(requestID, sessionChannel, payload)
	case ssh2.RequestTypeShell:
		return s.onShell(requestID, sessionChannel)
	case ssh2.RequestTypeExec:
		return s.onExec(requestID, sessionChannel, payload)
	case ssh2.RequestTypeSubsystem:
		return s.onSubsystem(requestID, sessionChannel, payload)
	case ssh2.RequestTypeWindow:
		return s.onChannel(requestID, sessionChannel, payload)
	case ssh2.RequestTypeSignal:
		return s.onSignal(requestID, sessionChannel, payload)
	case ssh2.RequestTypeX11:
		return s.onX11(channelMetadata.Connection.ConnectionID, requestID, sessionChannel, payload)
	}
	return nil
}

func (s *serverImpl) onEnvRequest(requestID uint64, sessionChannel SessionChannelHandler, payload interface{}) error {
	return sessionChannel.OnEnvRequest(
		requestID,
		payload.(ssh2.EnvRequestPayload).Name,
		payload.(ssh2.EnvRequestPayload).Value,
	)
}

func (s *serverImpl) onPtyRequest(requestID uint64, sessionChannel SessionChannelHandler, payload interface{}) error {
	return sessionChannel.OnPtyRequest(
		requestID,
		payload.(ssh2.PtyRequestPayload).Term,
		payload.(ssh2.PtyRequestPayload).Columns,
		payload.(ssh2.PtyRequestPayload).Rows,
		payload.(ssh2.PtyRequestPayload).Width,
		payload.(ssh2.PtyRequestPayload).Height,
		payload.(ssh2.PtyRequestPayload).ModeList,
	)
}

func (s *serverImpl) onShell(
	requestID uint64,
	sessionChannel SessionChannelHandler,
) error {
	return sessionChannel.OnShell(
		requestID,
	)
}

func (s *serverImpl) onExec(
	requestID uint64,
	sessionChannel SessionChannelHandler,
	payload interface{},
) error {
	return sessionChannel.OnExecRequest(
		requestID,
		payload.(ssh2.ExecRequestPayload).Exec,
	)
}

func (s *serverImpl) onSignal(requestID uint64, sessionChannel SessionChannelHandler, payload interface{}) error {
	return sessionChannel.OnSignal(
		requestID,
		payload.(ssh2.SignalRequestPayload).Signal,
	)
}

func (s *serverImpl) onForwardTCPIP(authenticatedMetadata metadata.ConnectionAuthenticatedMetadata, requestID uint64, payload interface{}, connection SSHConnectionHandler) error {
	fwdAddress := payload.(ssh2.ForwardTCPIPRequestPayload).Address
	fwdPort := payload.(ssh2.ForwardTCPIPRequestPayload).Port

	s.lock.Lock()
	defer s.lock.Unlock()
	conn, ok := s.connMap[authenticatedMetadata.ConnectionID]
	if !ok {
		return fmt.Errorf("Couldn't find connection in map, something terrible happened")
	}

	reverseForwardHandler := ReverseForwardHandler{
		sshConn: conn.sshConn,
		server:  s,
		logger:  s.logger,
	}
	err := connection.OnRequestTCPReverseForward(fwdAddress, fwdPort, &reverseForwardHandler)
	if err != nil {
		s.logger.Warning("Failed to forward tcpip %+v", err)
	}
	return err
}

func (s *serverImpl) onForwardStreamLocal(authenticatedMetadata metadata.ConnectionAuthenticatedMetadata, requestID uint64, payload interface{}, connection SSHConnectionHandler) error {
	path := payload.(ssh2.StreamLocalForwardRequestPayload).SocketPath
	s.lock.Lock()
	defer s.lock.Unlock()
	conn, ok := s.connMap[authenticatedMetadata.ConnectionID]
	if !ok {
		return fmt.Errorf("Couldn't find connection in map, something terrible happened")
	}

	reverseForwardHandler := ReverseForwardHandler{
		sshConn: conn.sshConn,
		server:  s,
		logger:  s.logger,
	}
	err := connection.OnRequestStreamLocal(path, &reverseForwardHandler)
	if err != nil {
		s.logger.Warning("Failed to forward streamlocal %+v", err)
	}
	return err
}

func (s *serverImpl) onCancelForward(authenticatedMetadata metadata.ConnectionAuthenticatedMetadata, requestID uint64, payload interface{}, connection SSHConnectionHandler) error {
	fwdAddress := payload.(ssh2.ForwardTCPIPRequestPayload).Address
	fwdPort := payload.(ssh2.ForwardTCPIPRequestPayload).Port

	return connection.OnRequestCancelTCPReverseForward(fwdAddress, fwdPort)
}

func (s *serverImpl) onCancelForwardStreamLocal(authenticatedMetadata metadata.ConnectionAuthenticatedMetadata, requestID uint64, payload interface{}, connection SSHConnectionHandler) error {
	path := payload.(ssh2.StreamLocalForwardRequestPayload).SocketPath

	return connection.OnRequestCancelStreamLocal(path)
}

func (s *serverImpl) onX11(connectionID string, requestID uint64, sessionChannel SessionChannelHandler, payload interface{}) error {
	x11 := payload.(ssh2.X11RequestPayload)
	s.logger.Debug("onX11: Handling X11 %+v", x11)

	s.lock.Lock()
	defer s.lock.Unlock()
	conn, ok := s.connMap[connectionID]
	if !ok {
		return fmt.Errorf("Couldn't find connection in map, something terrible happened")
	}

	reverseForwardHandler := ReverseForwardHandler{
		sshConn: conn.sshConn,
		server:  s,
		logger:  s.logger,
	}
	err := sessionChannel.OnX11Request(requestID, x11.SingleConnection, x11.Protocol, x11.Cookie, x11.Screen, &reverseForwardHandler)
	if err != nil {
		s.logger.Warning("Failed to start X11 forwarding %+v", err)
	}
	return err
}

func (s *serverImpl) onSubsystem(
	requestID uint64,
	sessionChannel SessionChannelHandler,
	payload interface{},
) error {
	return sessionChannel.OnSubsystem(
		requestID,
		payload.(ssh2.SubsystemRequestPayload).Subsystem,
	)
}

func (s *serverImpl) onChannel(requestID uint64, sessionChannel SessionChannelHandler, payload interface{}) error {
	return sessionChannel.OnWindow(
		requestID,
		payload.(ssh2.WindowRequestPayload).Columns,
		payload.(ssh2.WindowRequestPayload).Rows,
		payload.(ssh2.WindowRequestPayload).Width,
		payload.(ssh2.WindowRequestPayload).Height,
	)
}

func (s *serverImpl) shutdownHandler(lifecycle service.Lifecycle, exited chan struct{}) {
	s.handler.OnShutdown(lifecycle.ShutdownContext())
	exited <- struct{}{}
}

type shutdownHandler interface {
	OnShutdown(shutdownContext context.Context)
}
