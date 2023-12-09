package auth

import (
	"go.containerssh.io/libcontainerssh/config"
	"go.containerssh.io/libcontainerssh/internal/metrics"
	"go.containerssh.io/libcontainerssh/log"
	"go.containerssh.io/libcontainerssh/message"
)

func NewPassThroughClient(
	authType AuthenticationType,
	cfg config.AuthPassThroughClientConfig,
	logger log.Logger,
	_ metrics.Collector,
) (PassThroughClient, error) {
	if err := cfg.Validate(); err != nil {
		return nil, message.Wrap(
			err,
			message.EAuthConfigError,
			"PassThrough configuration failed to validate",
		)
	}
	return &passthroughAuthClient{
		logger:         logger,
		enablePassword: true,
		enablePubKey:   true,
	}, nil
}
