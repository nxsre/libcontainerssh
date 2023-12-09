package local

import (
	"context"
	"errors"
	"fmt"
	"github.com/creack/pty"
	"github.com/gliderlabs/ssh"
	"github.com/pkg/sftp"
	"go.containerssh.io/libcontainerssh/internal/uacc"
	gossh "golang.org/x/crypto/ssh"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"go.containerssh.io/libcontainerssh/internal/sshserver"
	"go.containerssh.io/libcontainerssh/internal/unixutils"
	"go.containerssh.io/libcontainerssh/log"
	"go.containerssh.io/libcontainerssh/message"
)

type channelHandler struct {
	sshserver.AbstractSessionChannelHandler

	channelID         uint64
	networkHandler    *networkHandler
	connectionHandler *sshConnectionHandler
	username          string
	env               map[string]string
	pty               bool
	columns           uint32
	rows              uint32
	exitSent          bool
	x11               bool
	exec              *localExec
	session           sshserver.SessionChannel
}

var (
	vscodeContainerRunning bool
	containerName          = "vscode_runsc"
	pubKeyFile             = filepath.Join("/tmp/" + containerName + ".pub")
	priKeyFile             = filepath.Join("/tmp/", containerName)
)

const (
	xauth_path = "/usr/bin/xauth"
)

type localExec struct {
	*os.File
	ch     *channelHandler
	cmd    *exec.Cmd
	logger log.Logger
}

func (x *localExec) signal(ctx context.Context, signal string) error {
	x.logger.Debug("signal:::localExec::", signal)
	return nil
}

func (x *localExec) resize(ctx context.Context, row, col uint16) error {
	x.logger.Debug("resize:::pty::", row, col)
	if err := pty.Setsize(x.File, &pty.Winsize{
		Rows: row,
		Cols: col,
	}); err != nil {
		x.logger.Info("error resizing pty: ", err)
	}
	return nil
}

func (x *localExec) kill() error {
	x.logger.Debug("kill:::localExec")
	x.cmd.Process.Kill()
	x.ch.session.Close()
	return nil
}

func (x *localExec) term(ctx context.Context) error {
	x.logger.Debug("term:::localExec")
	x.cmd.Process.Kill()
	x.ch.session.CloseWrite()
	return nil
}

func (x *localExec) done() <-chan struct{} {
	return nil
}

func (c *channelHandler) Context() ssh.Context {
	return c.connectionHandler.Context()
}

func (c *channelHandler) OnEnvRequest(_ uint64, name string, value string) error {
	c.networkHandler.mutex.Lock()
	defer c.networkHandler.mutex.Unlock()
	if c.exec != nil {
		return message.UserMessage(message.EDockerProgramAlreadyRunning, "program already running", "program already running")
	}
	c.env[name] = value
	return nil
}

func (c *channelHandler) OnPtyRequest(
	_ uint64,
	term string,
	columns uint32,
	rows uint32,
	_ uint32,
	_ uint32,
	_ []byte,
) error {
	c.networkHandler.mutex.Lock()
	defer c.networkHandler.mutex.Unlock()

	if c.exec != nil {
		return message.UserMessage(message.EDockerProgramAlreadyRunning, "program already running", "program already running")
	}
	c.env["TERM"] = term
	c.rows = rows
	c.columns = columns
	c.pty = true

	return nil
}

func (c *channelHandler) parseProgram(program string) []string {
	if program == "bash" {
		return []string{"/usr/local/bin/bash"}
	}
	programParts, err := unixutils.ParseCMD(program)
	if err != nil {
		return []string{"/bin/sh", "-c", program}
	} else {
		if strings.HasPrefix(programParts[0], "/") || strings.HasPrefix(
			programParts[0],
			"./",
		) || strings.HasPrefix(programParts[0], "../") {
			return programParts
		} else {
			return []string{"/bin/sh", "-c", program}
		}
	}
}

func (c *channelHandler) run(
	ctx context.Context,
	program []string,
) error {
	c.networkHandler.mutex.Lock()
	defer c.networkHandler.mutex.Unlock()
	if c.exec != nil {
		return message.UserMessage(message.EDockerProgramAlreadyRunning, "program already running", "program already running")
	}

	if c.connectionHandler.Context().Value(sshserver.ContextKeyVirtualStudioCode) != nil && c.connectionHandler.Context().Value(sshserver.ContextKeyVirtualStudioCode).(bool) {
		c.networkHandler.logger.Info("============= vscode 执行命令", program)
		if strings.TrimSpace(strings.Join(program, " ")) == "/bin/bash" {
			program = []string{"/usr/local/bin/bash"}
		}
		if c.connectionHandler.sshClient == nil {
			return message.NewMessage("安全环境运行失败", "检查错误")
		}
		// 建立新会话
		session, err := c.connectionHandler.sshClient.NewSession()
		if err != nil {
			return err
		}

		session.Setenv("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
		stdout, _ := session.StdoutPipe()
		stderr, _ := session.StderrPipe()
		stdin, _ := session.StdinPipe()

		go func() {
			_, _ = io.Copy(c.session.Stderr(), stderr)
		}()

		go func() {
			_, _ = io.Copy(c.session.Stdout(), stdout)
		}()

		go func() {
			_, _ = io.Copy(stdin, c.session.Stdin())
			stdin.Close()
		}()

		if c.pty {
			if err = session.Shell(); err != nil {
				return err
			}
		} else {
			if err = session.Start(strings.Join(program, " ")); err != nil {
				return err
			}
		}

		// 后台等待连接结束并关闭 session ，不阻塞
		go func() {
			defer session.Close()
			defer c.session.Close()
			if err := session.Wait(); err != nil {
				if e, ok := err.(*gossh.ExitError); ok {
					c.session.ExitStatus(uint32(e.ExitStatus()))
					switch e.ExitStatus() {
					case 130:
						return
					}
				}
				return
			} else {
				c.session.ExitStatus(0)
			}
		}()
		return nil
	}

	cmd := exec.Command(program[0], append(program[1:])...)
	if len(program) >= 3 {
		cmd = exec.Command(program[0], program[1], program[2])
	}

	user, err := user.Lookup(c.username)
	if err == nil {
		c.networkHandler.logger.Info(fmt.Sprintf("uid=%s,gid=%s", user.Uid, user.Gid))
		cmd.Dir = user.HomeDir
		uid, _ := strconv.Atoi(user.Uid)
		gid, _ := strconv.Atoi(user.Gid)
		if cmd.SysProcAttr == nil {
			cmd.SysProcAttr = &syscall.SysProcAttr{}
		}

		cmd.SysProcAttr.Credential = &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}
	} else {
		c.networkHandler.logger.Error(err)
		return err
	}
	cmd.Env = append(cmd.Env, fmt.Sprintf("HOME=%v", user.HomeDir))

	for k, v := range c.env {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%v=%v", k, v))
	}

	remote := c.networkHandler.client
	addr, err := uacc.PrepareAddr(&remote)
	if err != nil {
		c.networkHandler.logger.Error(err)
		return err
	}
	host := uacc.GetHost(remote.String())
	tty := os.NewFile(0, "/proc/self/fd/0")
	if c.pty {
		//ptmx, err := pty.Start(cmd)
		//if err != nil {
		//	return err
		//}
		c.networkHandler.logger.Info("打开终端")
		if cmd.SysProcAttr == nil {
			cmd.SysProcAttr = &syscall.SysProcAttr{}
		}
		cmd.SysProcAttr.Setsid = true
		cmd.SysProcAttr.Setctty = true
		ptmx, tty1, err := StartWithAttrs(cmd, nil, cmd.SysProcAttr)
		{
			uacc.PutLastlog("sshxx", c.username, c.networkHandler.client.String(), tty1.Name(), nil)
			err = uacc.Open("", "", c.username, host, addr, tty1.Name(), nil)
			if err != nil {
				c.networkHandler.logger.Error(err)
				return err
			}
		}

		err = pty.Setsize(ptmx, &pty.Winsize{Rows: uint16(c.rows), Cols: uint16(c.columns)})
		if err != nil {
			return err
		}

		c.exec = &localExec{File: ptmx, ch: c, cmd: cmd, logger: c.networkHandler.logger}
		go func() {
			_, err := io.Copy(c.exec.File, c.session.Stdin()) // stdin
			if err != nil && !errors.Is(err, io.EOF) {
				c.networkHandler.logger.Error(err)
			}
		}()
		go func() {
			_, err := io.Copy(c.session.Stdout(), c.exec.File) // stdout
			if err != nil && !errors.Is(err, io.EOF) {
				c.networkHandler.logger.Error(err)
			}
		}()
		// 不阻塞执行 cmd
		go func() {
			c.networkHandler.logger.Info("等待终端命令执行")
			cmd.Wait()
			c.session.ExitStatus(uint32(cmd.ProcessState.ExitCode()))
			c.session.Close()
			uacc.Close("", "", tty1.Name(), nil)
			_ = tty1.Close()
		}()
	} else {
		err := uacc.Open("", "", c.username, host, addr, "", tty)
		if err != nil {
			c.networkHandler.logger.Error(err)
			return err
		}
		uacc.PutLastlog("sshxx", c.username, c.networkHandler.client.String(), "", tty)
		//cmd.Stdout = c.session.Stdout()
		//cmd.Stderr = c.session.Stderr()
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			return err
		}
		stderr, err := cmd.StderrPipe()
		if err != nil {
			return err
		}
		stdin, err := cmd.StdinPipe()
		if err != nil {
			return err
		}

		wg := sync.WaitGroup{}
		go func(wg sync.WaitGroup) {
			_, err := io.Copy(stdin, c.session.Stdin())
			if err != nil && !errors.Is(err, io.EOF) {
				c.networkHandler.logger.Error(err)
			}
			c.session.Close()
		}(wg)

		wg.Add(2)
		go func(wg sync.WaitGroup) {
			_, err := io.Copy(c.session.Stderr(), stderr)
			if err != nil && !errors.Is(err, io.EOF) {
				c.networkHandler.logger.Error(err)
			}
			wg.Done()
		}(wg)

		go func(wg sync.WaitGroup) {
			_, err := io.Copy(c.session.Stdout(), stdout)
			if err != nil && !errors.Is(err, io.EOF) {
				c.networkHandler.logger.Error(err)
			}
			wg.Done()
		}(wg)

		err = cmd.Start()
		if err != nil {
			c.networkHandler.logger.Error(err)
			return err
		}

		go func() {
			c.networkHandler.logger.Info("等命令结束")
			err := cmd.Wait()
			if err != nil {
				c.networkHandler.logger.Error("命令退出异常", err)
			}
			c.networkHandler.logger.Info("退出 session")
			c.session.ExitStatus(uint32(cmd.ProcessState.ExitCode()))
			c.session.Close()
			wg.Wait()
			uacc.Close("", "", tty.Name(), nil)
			_ = tty.Close()
			c.networkHandler.logger.Info("结束************")
		}()
	}

	return nil

}

func (c *channelHandler) OnExecRequest(
	_ uint64,
	program string,
) error {
	startContext, cancelFunc := context.WithTimeout(context.Background(), 24*time.Hour)
	//defer cancelFunc()
	_ = cancelFunc
	c.networkHandler.logger.Debug("exec ***********", c.pty)
	if strings.HasSuffix(c.parseProgram(program)[0], "bash") {
		// 如果需要获取shell，但是显式关闭terminal，则标记为 vscode 请求
		c.session.Context().SetValue(sshserver.ContextKeyVirtualStudioCode, true)
	}

	return c.run(
		startContext,
		c.parseProgram(program),
	)
}

func (c *channelHandler) OnShell(
	_ uint64,
) error {
	startContext, cancelFunc := context.WithTimeout(context.Background(), 24*time.Hour)
	_ = cancelFunc
	if c.pty {
		return c.run(startContext, append(c.getDefaultShell(), "--login"))
	}

	// 如果需要获取shell，但是显式关闭terminal，则标记为 vscode 请求
	c.session.Context().SetValue(sshserver.ContextKeyVirtualStudioCode, true)
	return c.run(startContext, c.getDefaultShell())
}

func (c *channelHandler) getDefaultShell() []string {
	return []string{"/usr/local/bin/bash"}
	//shell, err := loginshell.Shell()
	//if err != nil {
	//	return []string{"/usr/local/bin/bash"}
	//}
	//return []string{shell}
}

type sftpChannel struct {
	sshserver.SessionChannel
}

func (s sftpChannel) Read(p []byte) (n int, err error) {
	return s.SessionChannel.Stdin().Read(p)
}

func (s sftpChannel) Write(p []byte) (n int, err error) {
	return s.SessionChannel.Stdout().Write(p)
}

func (s sftpChannel) Close() error {
	return s.SessionChannel.Close()
}

func (c *channelHandler) OnSubsystem(
	_ uint64,
	subsystem string,
) error {
	startContext, cancelFunc := context.WithTimeout(context.Background(), 24*time.Hour)
	_ = cancelFunc
	//defer cancelFunc()
	_ = startContext
	c.networkHandler.logger.Info(subsystem)
	if subsystem == "sftp" {
		serverOptions := []sftp.ServerOption{
			sftp.WithDebug(os.Stderr),
		}

		server, err := sftp.NewServer(
			&sftpChannel{c.session},
			serverOptions...,
		)
		if err != nil {
			c.networkHandler.logger.Error(err)
			return err
		}
		// 这里必须后台执行，和 c.run 行为一致，不能阻塞，否则 internal/sshserver/serverImpl.go:handleChannelRequest 中无法回复 reply 消息
		go func() {
			if err := server.Serve(); err != nil && err != io.EOF {
				c.networkHandler.logger.Error(err)
			}
			if err := server.Close(); err != nil {
				c.networkHandler.logger.Error(err)
			}
		}()
		return nil
	}
	//if binary, ok := c.networkHandler.config.Execution.Subsystems[subsystem]; ok {
	//	return c.run(startContext, []string{"/usr/libexec/openssh/sftp-server"})
	//}
	return message.UserMessage("SUBSYSTEM-NOT-SUPPORT", "subsystem not supported", "the specified subsystem is not supported (%s)", subsystem)
}

func (c *channelHandler) OnSignal(_ uint64, signal string) error {

	c.networkHandler.mutex.Lock()
	defer c.networkHandler.mutex.Unlock()
	if c.exec == nil {
		return message.UserMessage(
			message.EDockerProgramNotRunning,
			"Cannot send signal, program is not running.",
			"Cannot send signal, program is not running.",
		)
	}

	ctx, cancelFunc := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancelFunc()

	return c.exec.signal(ctx, signal)
}

func (c *channelHandler) OnWindow(_ uint64, columns uint32, rows uint32, _ uint32, _ uint32) error {
	c.networkHandler.logger.Info("xxxxxxxxxxx")
	c.networkHandler.mutex.Lock()
	defer c.networkHandler.mutex.Unlock()
	if c.exec == nil {
		return message.UserMessage(
			message.EDockerProgramNotRunning,
			"Cannot resize window, program is not running.",
			"Cannot resize window, program is not running.",
		)
	}

	ctx, _ := context.WithTimeout(context.Background(), 6*time.Second)
	//defer cancelFunc()

	return c.exec.resize(ctx, uint16(rows), uint16(columns))
}

func (c *channelHandler) OnX11Request(
	requestID uint64,
	singleConnection bool,
	proto string,
	cookie string,
	screen uint32,
	reverseHandler sshserver.ReverseForward,
) error {
	if c.x11 {
		return fmt.Errorf("X11 forwarding already setup for this channel")
	}

	c.connectionHandler.display = &Display{}
	if c.networkHandler.db.Last(c.connectionHandler.display, "lock = ?", 0).Error != nil {
		return fmt.Errorf("X11 forwarding is full")
	}
	c.connectionHandler.display.Lock = 1
	c.networkHandler.db.Save(c.connectionHandler.display)
	c.env["DISPLAY"] = fmt.Sprintf("localhost:%d", c.connectionHandler.display.ID)
	u, err := user.Lookup(c.username)
	if err != nil {
		return err
	}
	c.env["XAUTHORITY"] = path.Join(u.HomeDir, ".Xauthority")

	// 以目标用户身份执行 xauth add 命令
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	cc := []string{"-f", c.env["XAUTHORITY"], "add", fmt.Sprintf(":%d.%d", c.connectionHandler.display.ID, screen), proto, cookie}
	cmd := exec.Command(xauth_path, cc...)
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Credential = &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}

	bs, err := cmd.CombinedOutput()
	if err != nil {
		c.networkHandler.logger.Error("Failed to run xauth", err)
		return err
	}
	c.networkHandler.logger.Info("xauth========", string(bs))

	err = c.connectionHandler.agentForward.NewX11Forwarding(
		c.connectionHandler.setupAgent,
		c.networkHandler.logger,
		singleConnection,
		proto,
		cookie,
		screen,
		reverseHandler,
	)

	if err != nil {
		c.networkHandler.logger.Error(err)
		return err
	}

	c.x11 = true

	return nil
}

func (c *channelHandler) OnClose() {
	if c.exec != nil {
		c.exec.kill()
	}
}

func (c *channelHandler) OnShutdown(shutdownContext context.Context) {
	if c.exec != nil {
		c.exec.term(shutdownContext)
		// We wait for the program to exit. This is not needed in session or connection mode, but
		// later we will need to support persistent containers.
		select {
		case <-shutdownContext.Done():
			c.exec.kill()
		case <-c.exec.done():
		}
	}
}

func StartWithAttrs(c *exec.Cmd, sz *pty.Winsize, attrs *syscall.SysProcAttr) (*os.File, *os.File, error) {
	ptmx, tty, err := pty.Open()
	if err != nil {
		return nil, nil, err
	}

	if sz != nil {
		if err := pty.Setsize(ptmx, sz); err != nil {
			_ = ptmx.Close() // Best effort.
			return nil, nil, err
		}
	}
	if c.Stdout == nil {
		c.Stdout = tty
	}
	if c.Stderr == nil {
		c.Stderr = tty
	}
	if c.Stdin == nil {
		c.Stdin = tty
	}

	c.SysProcAttr = attrs

	if err := c.Start(); err != nil {
		_ = ptmx.Close() // Best effort.
		return nil, nil, err
	}
	return ptmx, tty, err
}
