package local

import (
	"context"
	"errors"
	"fmt"
	"github.com/gliderlabs/ssh"
	"go.containerssh.io/libcontainerssh/internal/agentforward"
	ssh2 "go.containerssh.io/libcontainerssh/internal/ssh"
	"go.containerssh.io/libcontainerssh/internal/sshserver"
	"go.containerssh.io/libcontainerssh/message"
	"go.containerssh.io/libcontainerssh/metadata"
	gossh "golang.org/x/crypto/ssh"
	"io"
	"os/exec"
	"os/user"
	"strconv"
	"syscall"
)

type sshConnectionHandler struct {
	networkHandler *networkHandler
	username       string
	env            map[string]string
	agentForward   agentforward.AgentForward
	agentCmd       *exec.Cmd
	display        *Display
	ctx            ssh.Context

	// vscode 模式进容器使用
	sshClient      *gossh.Client
	reverseHandler sshserver.ReverseForward
}

func (s *sshConnectionHandler) OnUnsupportedGlobalRequest(_ uint64, _ string, _ []byte) {}

func (b *sshConnectionHandler) OnFailedDecodeGlobalRequest(_ uint64, _ string, _ []byte, _ error) {}

func (s *sshConnectionHandler) OnUnsupportedChannel(_ uint64, _ string, _ []byte) {}

func (s *sshConnectionHandler) OnShutdown(context context.Context) {
	if s.agentForward != nil {
		s.agentForward.OnShutdown()
	}
}

func (s *sshConnectionHandler) Context() ssh.Context {
	return s.ctx
}

func (s *sshConnectionHandler) OnSessionChannel(
	meta metadata.ChannelMetadata,
	_ []byte,
	session sshserver.SessionChannel,
) (
	channel sshserver.SessionChannelHandler,
	failureReason sshserver.ChannelRejection,
) {
	return &channelHandler{
		channelID:         meta.ChannelID,
		networkHandler:    s.networkHandler,
		connectionHandler: s,
		username:          s.username,
		exitSent:          true,
		env:               map[string]string{},
		session:           session,
	}, nil
}

func (s *sshConnectionHandler) OnTCPForwardChannel(
	channelID uint64,
	hostToConnect string,
	portToConnect uint32,
	originatorHost string,
	originatorPort uint32,
) (channel sshserver.ForwardChannel, failureReason sshserver.ChannelRejection) {
	// 如果不是 vscode 标记的请求，则返回错误，拒绝端口转发
	s.networkHandler.logger.Info("xxxxxxxxxxxxxxx", s.Context().Value(sshserver.ContextKeyVirtualStudioCode))
	//if s.Context().Value(sshserver.ContextKeyVirtualStudioCode) == nil || !s.Context().Value(sshserver.ContextKeyVirtualStudioCode).(bool) {
	//	return nil, sshserver.NewChannelRejection(gossh.ConnectionFailed, "FORWARDING_FAILED", "Error setting up the forwarding", "Error setting up the forwarding")
	//}
	channel, err := s.agentForward.NewForwardTCP(
		s.setupAgent,
		s.networkHandler.logger,
		hostToConnect,
		portToConnect,
		originatorHost,
		originatorPort,
	)
	if err != nil {
		return nil, sshserver.NewChannelRejection(gossh.ConnectionFailed, "FORWARDING_FAILED", "Error setting up the forwarding", "Error setting up the forwarding")
	}
	return channel, nil
}

func (s *sshConnectionHandler) OnRequestTCPReverseForward(
	bindHost string,
	bindPort uint32,
	reverseHandler sshserver.ReverseForward,
) error {
	s.networkHandler.logger.Info("yyyyyyyyyyyyyy")
	// 在 ssh 命令行连接时拿不到 sshserver.ContextKeyVirtualStudioCode，因为 ssh 命令行中 request shell 在 request  tcpip-forward 之后执行
	//if s.Context().Value(sshserver.ContextKeyVirtualStudioCode) == nil || !s.Context().Value(sshserver.ContextKeyVirtualStudioCode).(bool) {
	//	return sshserver.NewChannelRejection(gossh.ConnectionFailed, "FORWARDING_FAILED", "Error setting up the forwarding", "Error setting up the forwarding")
	//}
	return s.agentForward.NewTCPReverseForwarding(
		s.setupAgent,
		s.networkHandler.logger,
		bindHost,
		bindPort,
		reverseHandler,
	)
}

func (s *sshConnectionHandler) OnRequestCancelTCPReverseForward(
	bindHost string,
	bindPort uint32,
) error {
	return s.agentForward.CancelTCPForwarding(bindHost, bindPort)
}

func (s *sshConnectionHandler) rejectAllRequests(req <-chan *gossh.Request) {
	for {
		req, ok := <-req
		if !ok {
			return
		}
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
	}
}

func (s *sshConnectionHandler) OnDirectStreamLocal(
	channelID uint64,
	path string,
) (channel sshserver.ForwardChannel, failureReason sshserver.ChannelRejection) {
	s.networkHandler.logger.Info("OnDirectStreamLocal=============", channelID, path)
	if s.Context().Value(sshserver.ContextKeyVirtualStudioCode) == nil || !s.Context().Value(sshserver.ContextKeyVirtualStudioCode).(bool) {
		return nil, sshserver.NewChannelRejection(gossh.ConnectionFailed, "FORWARDING_FAILED", "Error setting up the forwarding", "Error setting up the forwarding")
	}

	if s.Context().Value(sshserver.ContextKeyVirtualStudioCode).(bool) {
		payload := ssh2.DirectStreamLocalChannelOpenPayload{
			SocketPath: path,
		}
		mar := gossh.Marshal(payload)
		backingChannel, req, err := s.sshClient.OpenChannel(sshserver.ChannelTypeDirectStreamLocal, mar)
		if err != nil {
			realErr := &gossh.OpenChannelError{}
			if errors.As(err, &realErr) {
				failureReason = sshserver.NewChannelRejection(
					realErr.Reason,
					message.ESSHProxyBackendForwardFailed,
					realErr.Message,
					"Backend rejected channel with message: %s",
					realErr.Message,
				)
			} else {
				failureReason = sshserver.NewChannelRejection(
					gossh.ConnectionFailed,
					message.ESSHProxyBackendForwardFailed,
					"Cannot open session.",
					"Backend rejected channel with message: %s",
					err.Error(),
				)
			}
			s.networkHandler.logger.Debug(failureReason)
			return nil, failureReason
		}
		go s.rejectAllRequests(req)

		return backingChannel, nil
	}

	channel, err := s.agentForward.NewForwardUnix(
		s.setupAgent,
		s.networkHandler.logger,
		path,
	)
	if err != nil {
		return nil, sshserver.NewChannelRejection(gossh.ConnectionFailed, message.EDockerForwardingFailed, "Error setting up the forwarding", "Error setting up the forwarding (%s)", err)
	}
	return channel, nil
}

func (s *sshConnectionHandler) OnRequestStreamLocal(
	path string,
	reverseHandler sshserver.ReverseForward,
) error {
	s.networkHandler.logger.Info("OnRequestStreamLocal=============", path)
	if s.Context().Value(sshserver.ContextKeyVirtualStudioCode) == nil || !s.Context().Value(sshserver.ContextKeyVirtualStudioCode).(bool) {
		return sshserver.NewChannelRejection(gossh.ConnectionFailed, "FORWARDING_FAILED", "Error setting up the forwarding", "Error setting up the forwarding")
	}
	if s.Context().Value(sshserver.ContextKeyVirtualStudioCode).(bool) {
		payload := ssh2.StreamLocalForwardRequestPayload{
			SocketPath: path,
		}
		mar := gossh.Marshal(payload)
		ok, _, err := s.sshClient.SendRequest(string(ssh2.RequestTypeStreamLocalForward), true, mar)
		if err != nil {
			return err
		}
		if !ok {
			m := message.NewMessage(
				message.ESSHProxyBackendRequestFailed,
				"Failed to request streamlocal because the backing SSH server rejected the request",
			)
			s.networkHandler.logger.Debug(m)
			return m
		}
		if s.reverseHandler == nil {
			s.reverseHandler = reverseHandler
		}
	}
	return s.agentForward.NewUnixReverseForwarding(
		s.setupAgent,
		s.networkHandler.logger,
		path,
		reverseHandler,
	)
}

func (s *sshConnectionHandler) OnRequestCancelStreamLocal(
	path string,
) error {
	return s.agentForward.CancelStreamLocalForwarding(path)
}

func (c *sshConnectionHandler) setupAgent() (io.Reader, io.Writer, error) {
	agent := []string{"/usr/local/bin/agent", "forward-server"}

	c.agentCmd = exec.CommandContext(context.Background(), agent[0], agent[1:]...)
	user, err := user.Lookup(c.username)
	if err == nil {
		c.agentCmd.Dir = user.HomeDir
		//log.Printf("uid=%s,gid=%s", user.Uid, user.Gid)

		uid, _ := strconv.Atoi(user.Uid)
		gid, _ := strconv.Atoi(user.Gid)

		c.agentCmd.SysProcAttr = &syscall.SysProcAttr{}
		c.agentCmd.SysProcAttr.Credential = &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}

	}
	if c.display != nil {
		c.agentCmd.Env = append(c.agentCmd.Environ(), fmt.Sprintf("DPX=%d", c.display.ID))
	}
	stdinWriter, _ := c.agentCmd.StdinPipe()
	stdoutReader, _ := c.agentCmd.StdoutPipe()
	stderrReader, _ := c.agentCmd.StderrPipe()
	go func() {
		buf := make([]byte, 8192)
		for {
			nBytes, err := stderrReader.Read(buf)
			if nBytes != 0 {
				c.networkHandler.logger.Info(
					message.NewMessage(
						"AGENT_LOG",
						"%s",
						string(buf[:nBytes]),
					),
				)
			}
			if err != nil {
				return
			}
		}
	}()

	if err := c.agentCmd.Start(); err != nil {
		c.networkHandler.logger.Emergency(err)
		return nil, nil, fmt.Errorf("port forwarding does not work in session mode")
	}

	go func() {
		c.agentCmd.Wait()
	}()

	return stdoutReader, stdinWriter, nil

}
