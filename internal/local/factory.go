package local

import (
	"github.com/glebarez/sqlite"
	"go.containerssh.io/libcontainerssh/config"
	"go.containerssh.io/libcontainerssh/internal/metrics"
	"go.containerssh.io/libcontainerssh/internal/sshserver"
	log2 "go.containerssh.io/libcontainerssh/log"
	"gorm.io/gorm"
	"net"
	"sync"
)

var (
	db *gorm.DB
)

func init() {
	var err error
	db, err = gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		//Logger: glogger.Default.LogMode(glogger.Info),
	})
	if err != nil {
		return
	}

	db.Migrator().AutoMigrate(&Display{})

	for i := 0; i < 5; i++ {
		db.Create(&Display{})
	}

	var dps []Display
	db.Model(Display{}).Find(&dps)
}

// New creates a new NetworkConnectionHandler for a specific client.
func New(
	client net.TCPAddr,
	connectionID string,
	cfg config.LocalConfig,
	logger log2.Logger,
	backendRequestsMetric metrics.SimpleCounter,
	backendFailuresMetric metrics.SimpleCounter,
) (
	sshserver.NetworkConnectionHandler,
	error,
) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	abs := sshserver.AbstractNetworkConnectionHandler{}
	return &networkHandler{
		AbstractNetworkConnectionHandler: abs,
		mutex:                            &sync.Mutex{},
		client:                           client,
		connectionID:                     connectionID,
		//config:       cfg,
		logger:       logger,
		disconnected: false,
		db:           db,
		done:         make(chan struct{}),
	}, nil
}

type Display struct {
	gorm.Model
	Lock int
}
