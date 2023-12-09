package local

import (
	"errors"
	"fmt"
	"github.com/containerd/console"
	"github.com/creack/pty"
	"github.com/google/go-containerregistry/pkg/crane"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	jsoniter "github.com/json-iterator/go"
	archiver "github.com/mholt/archiver/v3"
	"github.com/opencontainers/runc/libcontainer/utils"
	"golang.org/x/term"
	"io"
	"io/fs"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
)

type OCIConfig struct {
	OciVersion string   `json:"ociVersion"`
	Process    Process  `json:"process"`
	Root       Root     `json:"root"`
	Hostname   string   `json:"hostname"`
	Mounts     []Mounts `json:"mounts"`
	Hooks      Hooks    `json:"hooks"`
	Linux      Linux    `json:"linux"`
}
type ConsoleSize struct {
	Height int `json:"height"`
	Width  int `json:"width"`
}
type User struct {
	UID            int   `json:"uid"`
	Gid            int   `json:"gid"`
	AdditionalGids []int `json:"additionalGids"`
}
type Capabilities struct {
	Bounding  []string `json:"bounding"`
	Effective []string `json:"effective"`
	Permitted []string `json:"permitted"`
}
type Process struct {
	Terminal        bool         `json:"terminal"`
	ConsoleSize     ConsoleSize  `json:"consoleSize"`
	User            User         `json:"user"`
	Args            []string     `json:"args"`
	Env             []string     `json:"env"`
	Cwd             string       `json:"cwd"`
	Capabilities    Capabilities `json:"capabilities"`
	ApparmorProfile string       `json:"apparmorProfile"`
	OomScoreAdj     int          `json:"oomScoreAdj"`
}
type Root struct {
	Path string `json:"path"`
}
type Mounts struct {
	Destination string   `json:"destination,omitempty"`
	Type        string   `json:"type,omitempty"`
	Source      string   `json:"source,omitempty"`
	Options     []string `json:"options,omitempty"`
}
type Hook struct {
	Path    string   `json:"path,omitempty"`
	Args    []string `json:"args,omitempty"`
	Env     []string `json:"env,omitempty"`
	Timeout int      `json:"timeout,omitempty"`
}
type Hooks struct {
	Prestart        []Hook `json:"prestart,omitempty"`
	CreateRuntime   []Hook `json:"createRuntime,omitempty"`
	CreateContainer []Hook `json:"createContainer,omitempty"`
	StartContainer  []Hook `json:"startContainer,omitempty"`
	Poststart       []Hook `json:"poststart,omitempty"`
	Poststop        []Hook `json:"poststop,omitempty"`
}
type Sysctl struct {
	NetIpv4IPUnprivilegedPortStart string `json:"net.ipv4.ip_unprivileged_port_start"`
	NetIpv4PingGroupRange          string `json:"net.ipv4.ping_group_range"`
}
type Devices struct {
	Allow  bool   `json:"allow"`
	Access string `json:"access"`
	Type   string `json:"type,omitempty"`
	Major  int    `json:"major,omitempty"`
	Minor  int    `json:"minor,omitempty"`
}
type Memory struct {
}
type CPU struct {
	Shares int `json:"shares"`
}
type BlockIO struct {
	Weight int `json:"weight"`
}
type Resources struct {
	Devices []Devices `json:"devices"`
	Memory  Memory    `json:"memory"`
	CPU     CPU       `json:"cpu"`
	BlockIO BlockIO   `json:"blockIO"`
}
type Namespaces struct {
	Type string `json:"type"`
}
type Args struct {
	Index int    `json:"index"`
	Value int    `json:"value"`
	Op    string `json:"op"`
}
type Syscalls struct {
	Names    []string `json:"names"`
	Action   string   `json:"action"`
	Args     []Args   `json:"args,omitempty"`
	ErrnoRet int      `json:"errnoRet,omitempty"`
}
type Seccomp struct {
	DefaultAction   string     `json:"defaultAction,omitempty"`
	DefaultErrnoRet int        `json:"defaultErrnoRet,omitempty"`
	Architectures   []string   `json:"architectures,omitempty"`
	Syscalls        []Syscalls `json:"syscalls,omitempty"`
}
type Linux struct {
	Sysctl        Sysctl       `json:"sysctl"`
	Resources     Resources    `json:"resources"`
	CgroupsPath   string       `json:"cgroupsPath"`
	Namespaces    []Namespaces `json:"namespaces"`
	Seccomp       Seccomp      `json:"seccomp,omitempty"`
	MaskedPaths   []string     `json:"maskedPaths"`
	ReadonlyPaths []string     `json:"readonlyPaths"`
}

var ociConfigStr = `
{
  "ociVersion": "1.1.0-rc.2",
  "process": {
    "terminal": true,
    "consoleSize": {
      "height": 58,
      "width": 175
    },
    "user": {
      "uid": 0,
      "gid": 0,
      "additionalGids": [
        0,
        0
      ]
    },
    "args": [
      "/bin/bash","/entry.sh", "/usr/sbin/sshd", "-D", "-e", "-f", "/etc/ssh/sshd_config"
    ],
    "env": [
      "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
      "HOSTNAME=netshoot",
      "TERM=xterm",
      "SSH_ENABLE_PASSWORD_AUTH=true",
      "TCP_FORWARDING=true"
    ],
    "cwd": "/root",
    "capabilities": {
      "bounding": [
        "CAP_CHOWN",
        "CAP_DAC_OVERRIDE",
        "CAP_FSETID",
        "CAP_FOWNER",
        "CAP_MKNOD",
        "CAP_NET_RAW",
        "CAP_SETGID",
        "CAP_SETUID",
        "CAP_SETFCAP",
        "CAP_SETPCAP",
        "CAP_NET_BIND_SERVICE",
        "CAP_SYS_CHROOT",
        "CAP_KILL",
        "CAP_AUDIT_WRITE"
      ],
      "effective": [
        "CAP_CHOWN",
        "CAP_DAC_OVERRIDE",
        "CAP_FSETID",
        "CAP_FOWNER",
        "CAP_MKNOD",
        "CAP_NET_RAW",
        "CAP_SETGID",
        "CAP_SETUID",
        "CAP_SETFCAP",
        "CAP_SETPCAP",
        "CAP_NET_BIND_SERVICE",
        "CAP_SYS_CHROOT",
        "CAP_KILL",
        "CAP_AUDIT_WRITE"
      ],
      "permitted": [
        "CAP_CHOWN",
        "CAP_DAC_OVERRIDE",
        "CAP_FSETID",
        "CAP_FOWNER",
        "CAP_MKNOD",
        "CAP_NET_RAW",
        "CAP_SETGID",
        "CAP_SETUID",
        "CAP_SETFCAP",
        "CAP_SETPCAP",
        "CAP_NET_BIND_SERVICE",
        "CAP_SYS_CHROOT",
        "CAP_KILL",
        "CAP_AUDIT_WRITE"
      ]
    },
    "apparmorProfile": "docker-default",
    "oomScoreAdj": 0
  },
  "root": {
    "path": ""
  },
  "hostname": "a8401ed642a0",
  "mounts": [
    {
      "destination": "/proc",
      "type": "proc",
      "source": "proc",
      "options": [
        "nosuid",
        "noexec",
        "nodev"
      ]
    },
    {
      "destination": "/dev",
      "type": "tmpfs",
      "source": "tmpfs",
      "options": [
        "nosuid",
        "strictatime",
        "mode=755",
        "size=65536k"
      ]
    },
    {
      "destination": "/dev/pts",
      "type": "devpts",
      "source": "devpts",
      "options": [
        "nosuid",
        "noexec",
        "newinstance",
        "ptmxmode=0666",
        "mode=0620",
        "gid=5"
      ]
    },
    {
      "destination": "/sys",
      "type": "sysfs",
      "source": "sysfs",
      "options": [
        "nosuid",
        "noexec",
        "nodev",
        "ro"
      ]
    },
    {
      "destination": "/sys/fs/cgroup",
      "type": "cgroup",
      "source": "cgroup",
      "options": [
        "ro",
        "nosuid",
        "noexec",
        "nodev"
      ]
    },
    {
      "destination": "/dev/mqueue",
      "type": "mqueue",
      "source": "mqueue",
      "options": [
        "nosuid",
        "noexec",
        "nodev"
      ]
    },
    {
      "destination": "/dev/shm",
      "type": "tmpfs",
      "source": "shm",
      "options": [
        "nosuid",
        "noexec",
        "nodev",
        "mode=1777",
        "size=67108864"
      ]
    },
    {
      "destination": "/dev/virtio-ports",
      "type": "bind",
      "source": "/dev/virtio-ports",
      "options": [
        "rbind",
        "rprivate"
      ]
    },
    {
      "destination": "/root",
      "type": "bind",
      "source": "/root",
      "options": [
        "rbind",
        "rprivate"
      ]
    },
    {
      "destination": "/opt",
      "type": "bind",
      "source": "/opt",
      "options": [
        "rbind",
        "rprivate"
      ]
    },
	{
      "destination": "/tmp",
      "type": "bind",
      "source": "/tmp",
      "options": [
        "rbind",
        "rprivate"
      ]
    },
	{
      "destination": "/home",
      "type": "bind",
      "source": "/home",
      "options": [
        "rbind",
        "rprivate"
      ]
    },
	{
      "destination": "/etc/profile",
      "type": "bind",
      "source": "/etc/profile",
      "options": [
        "rbind",
        "rprivate"
      ]
    },
	{
      "destination": "/etc/bashrc",
      "type": "bind",
      "source": "/etc/bashrc",
      "options": [
        "rbind",
        "rprivate"
      ]
    },
	{
      "destination": "/etc/profile.d",
      "type": "bind",
      "source": "/etc/profile.d",
      "options": [
        "rbind",
        "rprivate"
      ]
    },
	{
      "destination": "/etc/passwd",
      "type": "bind",
      "source": "/etc/passwd",
      "options": [
        "rbind",
        "rprivate"
      ]
    },
	{
      "destination": "/etc/shadow",
      "type": "bind",
      "source": "/etc/shadow",
      "options": [
        "rbind",
        "rprivate"
      ]
    },
	{
      "destination": "/etc/group",
      "type": "bind",
      "source": "/etc/group",
      "options": [
        "rbind",
        "rprivate"
      ]
    },
	{
      "destination": "/etc/ssh/keys",
      "type": "bind",
      "source": "/etc/ssh/keys",
      "options": [
        "rbind",
        "rprivate"
      ]
    },
	{
      "destination": "/root/.ssh/authorized_keys",
      "type": "bind",
      "source": "/tmp/vscode_runsc.pub",
      "options": [
        "rbind",
        "rprivate"
      ]
    },
    {
      "destination": "/etc/resolv.conf",
      "type": "bind",
      "source": "/etc/resolv.conf",
      "options": [
        "rbind",
        "rprivate"
      ]
    },
    {
      "destination": "/etc/hostname",
      "type": "bind",
      "source": "/etc/hostname",
      "options": [
        "rbind",
        "rprivate"
      ]
    },
    {
      "destination": "/etc/hosts",
      "type": "bind",
      "source": "/etc/hosts",
      "options": [
        "rbind",
        "rprivate"
      ]
    },
	{
      "destination": "/sys/firmware/dmi/tables",
      "type": "bind",
      "source": "/sys/firmware/dmi/tables",
      "options": [
        "rbind",
        "rprivate"
      ]
    },
	{
      "destination": "/var/log/odv",
      "type": "bind",
      "source": "/var/log/odv",
      "options": [
        "rbind",
        "rprivate"
      ]
    },
	{
      "destination": "/usr/libexec",
      "type": "bind",
      "source": "/usr/libexec",
      "options": [
        "rbind",
        "rprivate"
      ]
    },
	{
      "destination": "/usr/local/bin/bash",
      "type": "bind",
      "source": "/usr/local/bin/bash",
      "options": [
        "rbind",
        "rprivate"
      ]
    }
  ],
  "linux": {
    "sysctl": {
      "net.ipv4.ip_unprivileged_port_start": "0",
      "net.ipv4.ping_group_range": "0 2147483647"
    },
    "resources": {
      "devices": [
        {
          "allow": false,
          "access": "rwm"
        },
        {
          "allow": true,
          "type": "c",
          "major": 1,
          "minor": 5,
          "access": "rwm"
        },
        {
          "allow": true,
          "type": "c",
          "major": 1,
          "minor": 3,
          "access": "rwm"
        },
        {
          "allow": true,
          "type": "c",
          "major": 1,
          "minor": 9,
          "access": "rwm"
        },
        {
          "allow": true,
          "type": "c",
          "major": 1,
          "minor": 8,
          "access": "rwm"
        },
        {
          "allow": true,
          "type": "c",
          "major": 5,
          "minor": 0,
          "access": "rwm"
        },
        {
          "allow": true,
          "type": "c",
          "major": 5,
          "minor": 1,
          "access": "rwm"
        },
        {
          "allow": false,
          "type": "c",
          "major": 10,
          "minor": 229,
          "access": "rwm"
        }
      ],
      "memory": {},
      "cpu": {
        "shares": 0
      },
      "blockIO": {
        "weight": 0
      }
    },
    "namespaces": [
      {
        "type": "mount"
      },
      {
        "type": "uts"
      },
      {
        "type": "pid"
      },
      {
        "type": "ipc"
      },
      {
        "type": "cgroup"
      }
    ],
    "maskedPaths": [
      "/proc/asound",
      "/proc/acpi",
      "/proc/kcore",
      "/proc/keys",
      "/proc/latency_stats",
      "/proc/timer_list",
      "/proc/timer_stats",
      "/proc/sched_debug",
      "/proc/scsi",
      "/sys/firmware"
    ],
    "readonlyPaths": [
      "/proc/bus",
      "/proc/fs",
      "/proc/irq",
      "/proc/sys",
      "/proc/sysrq-trigger"
    ]
  }
}
`

var podInitStr = `
{
  "trace_session": {
    "name": "Default",
    "points": [
      {
        "name": "container/start"
      },
      {
        "name": "sentry/clone"
      },
      {
        "name": "sentry/task_exit"
      },
      {
        "name": "sentry/execve"
      },
      {
        "name": "sentry/exit_notify_parent"
      },
      {
        "name": "syscall/openat/enter"
      },
      {
        "name": "syscall/openat/exit"
      },
      {
        "name": "syscall/read/enter",
        "optional_fields": [
          "fd_path"
        ],
        "context_fields": [
          "time",
          "container_id",
          "thread_id"
        ]
      },
      {
        "name": "syscall/read/exit"
      },
      {
        "name": "syscall/sysno/1/enter",
        "context_fields": [
          "time",
          "container_id"
        ]
      },
      {
        "name": "syscall/sysno/1/exit"
      },
      {
        "name": "syscall/sysno/0/enter",
        "context_fields": [
          "time",
          "container_id",
          "thread_id",
          "credentials",
          "cwd"
        ]
      }
    ],
    "sinks": [
      {
        "name": "remote",
        "config": {
          "endpoint": "/tmp/gvisor.sock",
          "retries": 3
        },
        "ignore_setup_error": false
      }
    ]
  }
}
`

func handleTTY(path string, noStdin bool, stdout, stdin *os.File, ch chan os.Signal, waitTty *sync.WaitGroup) error {
	// Open a socket.
	ln, err := net.Listen("unix", path)
	waitTty.Done()

	if err != nil {
		return err
	}
	defer ln.Close()

	// We only accept a single connection, since we can only really have
	// one reader for os.Stdin. Plus this is all a PoC.
	conn, err := ln.Accept()
	if err != nil {
		return err
	}
	defer conn.Close()

	// Close ln, to allow for other instances to take over.
	ln.Close()

	// Get the fd of the connection.
	unixconn, ok := conn.(*net.UnixConn)
	if !ok {
		return errors.New("failed to cast to unixconn")
	}

	socket, err := unixconn.File()
	if err != nil {
		return err
	}
	defer socket.Close()

	// Get the master file descriptor from runC.
	master, err := utils.RecvFd(socket)
	if err != nil {
		return err
	}

	c, err := console.ConsoleFromFile(master)
	if err != nil {
		return err
	}

	//if err := console.ClearONLCR(c.Fd()); err != nil {
	//	return err
	//}

	go func() {
		for w := range ch {
			switch w {
			case syscall.SIGWINCH:
				size, err := pty.GetsizeFull(stdin)
				if err != nil {
					log.Fatalln(err)
				}
				c.Resize(console.WinSize{Height: size.Rows, Width: size.Cols})
			}
		}
	}()
	ch <- syscall.SIGWINCH

	// Copy from our stdio to the master fd.
	var (
		wg            sync.WaitGroup
		inErr, outErr error
	)
	wg.Add(1)
	go func() {
		_, outErr = io.Copy(stdout, c)
		wg.Done()
	}()
	if !noStdin {
		wg.Add(1)
		go func() {
			_, inErr = io.Copy(c, stdin)
			wg.Done()
		}()
	}

	// Only close the master fd once we've stopped copying.
	wg.Wait()
	c.Close()

	if outErr != nil {
		return outErr
	}

	return inErr
}

func createVscodeContainer(cname string) error {
	ptmx, ptty, err := pty.Open()
	if err != nil {
		return err
	}

	{
		// Handle pty size.
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGWINCH)
		go func() {
			for range ch {
				if err := pty.InheritSize(os.Stdin, ptmx); err != nil {
					log.Printf("error resizing pty: %s", err)
				}
			}
		}()
		ch <- syscall.SIGWINCH                        // Initial resize.
		defer func() { signal.Stop(ch); close(ch) }() // Cleanup signals when done.
	}

	// 关闭重复回显
	term.MakeRaw(int(ptty.Fd()))

	rootPath := "/var/run/runtime-runc/odv"
	os.RemoveAll(rootPath)
	err = os.MkdirAll(rootPath, fs.ModeDir)
	if err != nil {
		return err
	}

	err = os.MkdirAll("/var/log/runc/", fs.ModeDir)
	if err != nil {
		return err
	}

	var socket = filepath.Join(rootPath, fmt.Sprintf("pty-%s.sock", cname))
	{
		// 等待创建 tty socket
		waitTty := sync.WaitGroup{}
		waitTty.Add(1)
		go func() {
			ch1 := make(chan os.Signal, 1)
			signal.Notify(ch1, syscall.SIGWINCH)
			err := handleTTY(socket, false, ptty, ptty, ch1, &waitTty)
			if err != nil {
				log.Println(err)
				return
			}
		}()
		os.Remove(socket)
		waitTty.Wait()
	}

	podInitFile := filepath.Join(rootPath, "pod_init.json")
	{
		file, err := os.OpenFile(podInitFile, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, fs.ModePerm)
		if err != nil {
			return err
		}
		file.WriteString(podInitStr)
		file.Close()
	}

	// 修改 dmi 权限
	func() {
		dmiTable := "/sys/firmware/dmi/tables/"
		files, err := os.ReadDir(dmiTable)
		if err != nil {
			return
		}
		for _, file := range files {
			os.Chmod(filepath.Join(dmiTable, file.Name()), 444)
		}
	}()

	// 创建容器
	bundle := filepath.Join("/run/containerd/io.containerd.runtime.v2.task/odv", cname)
	os.RemoveAll(bundle)

	rootfs := filepath.Join(bundle, "rootfs")
	os.MkdirAll(rootfs, os.ModePerm)

	// 镜像导出 rootfs
	//err = image2rootfs("registry.docker.com/library/ubuntu:jammy", filepath.Join(bundle, "rootfs"))
	rootfsPath := filepath.Join(bundle, "rootfs")
	// 联通环境  10.185.8.245/library/sshd
	err = image2rootfs("10.185.8.245/library/sshd", rootfsPath)
	//err = image2rootfs("registry.docker.com/nicolaka/netshoot:v0.11", filepath.Join(bundle, "rootfs"))
	if err != nil {
		return err
	}
	{
		u, _ := user.Lookup("root")
		ociConfig := OCIConfig{}
		jsoniter.UnmarshalFromString(ociConfigStr, &ociConfig)
		hostname, _ := os.Hostname()
		ociConfig.Hostname = hostname
		ociConfig.Process.Cwd = u.HomeDir
		ociConfig.Root.Path = rootfs

		// /usr/local/bin/audit_bash 替换掉 /bin/bash 以实现录屏审计功能
		ociConfig.Hooks.CreateRuntime = append(ociConfig.Hooks.CreateRuntime) //Hook{
		//	Path: "/usr/bin/mv",
		//	Args: []string{"-f", filepath.Join(rootfsPath, "/usr/local/bin/audit_bash"), filepath.Join(rootfsPath, "/usr/local/bin/bash")},
		//},
		//Hook{
		//	Path: "/usr/bin/mv",
		//	Args: []string{"-f", filepath.Join(rootfsPath, "/usr/local/bin/audit_bash"), filepath.Join(rootfsPath, "/bin/bash")},
		//},

		ociConfigStr, _ = jsoniter.MarshalToString(ociConfig)
		file, err := os.OpenFile(filepath.Join(bundle, "config.json"), os.O_TRUNC|os.O_CREATE|os.O_WRONLY, fs.ModePerm)
		if err != nil {
			return err
		}

		file.WriteString(ociConfigStr)
		file.Close()
	}

	create := exec.Command("runsc",
		"--root="+rootPath,
		"--pod-init-config="+podInitFile,
		"--network=host",
		"--rootless=false",
		"--debug-log="+fmt.Sprintf("/var/log/runc/%s-debug.log", cname),
		"--file-access=shared",
		//"--file-access=exclusive",
		"--overlay2=none",
		"create",
		"--bundle="+bundle,
		"--console-socket="+socket,
		cname,
	)

	create.Stdout = os.Stdout
	create.Stderr = os.Stderr

	err = create.Run()
	if err != nil {
		log.Println("crate failed: ", err)
		return err
	}

	start := exec.Command("runsc",
		"--root="+rootPath,
		"--network=host",
		"start",
		cname,
	)
	start.Stdout = os.Stdout
	start.Stderr = os.Stderr
	err = start.Run()
	if err != nil {
		log.Println("start failed: ", err, start.Args)
		return err
	}

	// 等待容器退出
	wait := exec.Command("runsc", "--root="+rootPath, "wait", cname)
	err = wait.Start()
	if err != nil {
		return err
	}

	// Make sure to close the pty at the end.
	defer func() {
		wait.Wait()
		_ = ptmx.Close()
	}() // Best effort.

	// Set stdin in raw mode.
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return err
	}
	defer func() { _ = term.Restore(int(os.Stdin.Fd()), oldState) }() // Best effort.

	// Copy stdin to the pty and the pty to stdout.
	// NOTE: The goroutine will keep reading until the next keystroke before returning.
	go func() { _, _ = io.Copy(ptmx, os.Stdin) }()

	go func() { _, _ = io.Copy(os.Stdout, ptmx) }()

	return nil
}

//func main() {
//	// 每次登录创建新容器
//	if err := createVscodeContainer("vscode_" + uuid.Generate().String()); err != nil {
//		log.Fatal(err)
//	}
//}

func image2rootfs(imageFullName, rootfsPath string) error {
	var (
		image v1.Image
		err   error
	)

	//1.从远程仓库拉取镜像
	image, err = crane.Pull(imageFullName,
		crane.Insecure,
		crane.WithPlatform(&v1.Platform{OS: runtime.GOOS, Architecture: runtime.GOARCH}))
	if err != nil {
		fmt.Println("crane.Pull function failed")
		return err
	}

	//2.获取镜像的哈希值
	m, err := image.Manifest()
	imageFullHash := m.Config.Digest.Hex
	fmt.Println("image hash:", imageFullHash)

	//3.创建镜像存储路径
	imageStorageDir := "/tmp" //默认值为tmp目录
	err = os.MkdirAll(imageStorageDir, 0755)
	if err != nil {
		fmt.Printf("mkdir %s failed!\n")
		return err
	}

	//4.保存镜像到存储路径,SaveLegacy保存的镜像格式为tarball
	//你也可采用SaveOCI函数完成这个功能
	//imagePath := imageStorageDir + "/package.tar"
	//err = crane.SaveLegacy(image, "registry.docker.com/library/ubuntu:jammy", imagePath)
	//if err != nil {
	//	fmt.Println("crane.SaveLegacy function failed", err)
	//	return
	//}
	//crane.SaveOCI(image, "/tmp/xxxxxxx")
	tmp, err := os.CreateTemp(os.TempDir(), "image_")
	if err != nil {
		fmt.Println("crane.export function failed", err)
		return err
	}
	defer func() {
		tmp.Close()
		os.Remove(tmp.Name())
	}()
	// 导出镜像
	err = crane.Export(image, tmp)
	if err != nil {
		return err
	}
	tar := archiver.NewTar()
	return tar.Unarchive(tmp.Name(), rootfsPath)
}
