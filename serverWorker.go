package libcontainerssh

import (
	"github.com/docker/docker/pkg/reexec"
	"go.containerssh.io/libcontainerssh/config"
	"go.containerssh.io/libcontainerssh/internal/geoip"
	"go.containerssh.io/libcontainerssh/internal/metrics"
	"go.containerssh.io/libcontainerssh/internal/sshserver"
	"go.containerssh.io/libcontainerssh/log"
	"go.containerssh.io/libcontainerssh/message"
	"go.containerssh.io/libcontainerssh/service"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
)

func init() {
	reexec.Register("containerssh-worker", Worker)
	if reexec.Init() {
		os.Exit(0)
	}
}

func Worker() {
	cfg := config.AppConfig{}
	cfg.Default()

	loggerFactory := log.NewLoggerFactory()
	logger, err := loggerFactory.Make(
		cfg.Log,
	)
	if err != nil {
		panic(err)
	}

	logger = logger.WithLabel("module", "worker")

	if !strings.HasSuffix(os.Args[0], "-worker") {
		return
	}
	configFile, actionDumpConfig, actionLicenses, actionHealthCheck = getArguments()

	if configFile == "" {
		configFile = "config.yaml"
	}
	realConfigFile, err := filepath.Abs(configFile)
	if err != nil {
		logger.Critical(
			message.Wrap(
				err,
				message.ECoreConfig,
				"Failed to fetch absolute path for configuration file %s",
				configFile,
			))
		os.Exit(1)
	}
	configFile = realConfigFile
	if err = readConfigFile(configFile, loggerFactory, &cfg); err != nil {
		logger.Critical(
			message.Wrap(
				err,
				message.ECoreConfig,
				"Invalid configuration in file %s",
				configFile,
			))
		os.Exit(1)
	}

	configuredLogger, err := loggerFactory.Make(
		cfg.Log,
	)
	if err != nil {
		logger.Critical(err)
		os.Exit(1)
	}

	configuredLogger.Debug(message.NewMessage(message.MCoreConfigFile, "Using configuration file %s...", configFile))
	server, err := newSshServer(cfg, loggerFactory)
	if err != nil {
		logger.Critical(err)
		os.Exit(1)
	}

	// 接管 net.Conn
	signal.Ignore(syscall.SIGHUP, syscall.SIGTERM)
	// 子进程
	// 从 fd 3 获取连接
	var c net.Conn
	if c, err = net.FileConn(os.NewFile(3, "connection")); err != nil {
		logger.Error("----------failed to obtain connection")
		return
	}
	server.WaitGroup().Add(1)
	server.HandleConnection(c)
	server.WaitGroup().Wait()
}

// New creates a new instance of ContainerSSH.
func newSshServer(cfg config.AppConfig, factory log.LoggerFactory) (sshserver.Server, error) {
	if err := cfg.Validate(false); err != nil {
		return nil, message.Wrap(err, message.ECoreConfig, "invalid ContainerSSH configuration")
	}

	logger, err := factory.Make(cfg.Log)
	if err != nil {
		return nil, err
	}

	pool := service.NewPool(
		service.NewLifecycleFactory(),
		logger.WithLabel("module", "service"),
	)

	geoIPLookupProvider, err := geoip.New(cfg.GeoIP)
	if err != nil {
		return nil, err
	}

	metricsCollector := metrics.New(geoIPLookupProvider)

	if err := createMetricsServer(cfg, logger, metricsCollector, pool); err != nil {
		return nil, err
	}

	containerBackend, err := createBackend(cfg, logger, metricsCollector)
	if err != nil {
		return nil, err
	}

	authHandler, err := createAuthHandler(cfg, logger, containerBackend, metricsCollector, pool)
	if err != nil {
		return nil, err
	}

	auditLogHandler, err := createAuditLogHandler(cfg, logger, authHandler, geoIPLookupProvider)
	if err != nil {
		return nil, err
	}

	metricsHandler, err := createMetricsBackend(cfg, metricsCollector, auditLogHandler)
	if err != nil {
		return nil, err
	}

	sshLogger := logger.WithLabel("module", "ssh")

	return sshserver.New("",
		cfg.SSH,
		metricsHandler,
		sshLogger,
	)
}
