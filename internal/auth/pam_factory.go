package auth

import (
	"go.containerssh.io/libcontainerssh/config"
	"go.containerssh.io/libcontainerssh/internal/metrics"
	"go.containerssh.io/libcontainerssh/log"
	"go.containerssh.io/libcontainerssh/message"
)

func NewPamClient(
	authType AuthenticationType,
	cfg config.AuthPAMClientConfig,
	logger log.Logger,
	_ metrics.Collector,
) (PamClient, error) {
	if err := cfg.Validate(); err != nil {
		return nil, message.Wrap(
			err,
			message.EAuthConfigError,
			"PAM configuration failed to validate",
		)
	}
	return &pamAuthClient{logger: logger}, nil
}
