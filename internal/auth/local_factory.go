package auth

import (
	"go.containerssh.io/libcontainerssh/config"
	"go.containerssh.io/libcontainerssh/internal/metrics"
	"go.containerssh.io/libcontainerssh/log"
)

// NewLocalClient creates a new localClient authentication client.
//
//goland:noinspection GoUnusedExportedFunction
func NewLocalClient(
	authType AuthenticationType,
	cfg config.LocalConfig,
	logger log.Logger,
	metrics metrics.Collector,
) (LocalClient, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	backendRequestsMetric, backendFailureMetric, authSuccessMetric, authFailureMetric := createMetrics(metrics)
	return &localClient{
		logger:                logger,
		metrics:               metrics,
		backendRequestsMetric: backendRequestsMetric,
		backendFailureMetric:  backendFailureMetric,
		authSuccessMetric:     authSuccessMetric,
		authFailureMetric:     authFailureMetric,
		enablePassword:        authType == AuthenticationTypePassword || authType == AuthenticationTypeAll,
		enablePubKey:          authType == AuthenticationTypePublicKey || authType == AuthenticationTypeAll,
		enableAuthz:           authType == AuthenticationTypeAuthz || authType == AuthenticationTypeAll,
	}, nil
}
