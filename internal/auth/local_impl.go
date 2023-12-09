package auth

import (
	"encoding/base64"
	"errors"
	"go.containerssh.io/libcontainerssh/auth"
	"go.containerssh.io/libcontainerssh/internal/metrics"
	"go.containerssh.io/libcontainerssh/log"
	"go.containerssh.io/libcontainerssh/message"
	"go.containerssh.io/libcontainerssh/metadata"
	"golang.org/x/crypto/ssh"
	"net"
	"os"
	"os/user"
	"path/filepath"
)

type localClient struct {
	logger                log.Logger
	metrics               metrics.Collector
	backendRequestsMetric metrics.SimpleCounter
	backendFailureMetric  metrics.SimpleCounter
	authSuccessMetric     metrics.GeoCounter
	authFailureMetric     metrics.GeoCounter
	enablePassword        bool
	enablePubKey          bool
	enableAuthz           bool
}

func (client *localClient) Password(
	meta metadata.ConnectionAuthPendingMetadata,
	password []byte,
) AuthenticationContext {
	if !client.enablePassword {
		err := message.UserMessage(
			message.EAuthDisabled,
			"Password authentication failed.",
			"Password authentication is disabled.",
		)
		client.logger.Debug(err)
		return &localClientContext{meta.AuthFailed(), false, err}
	}
	method := "Password"
	authType := "password"
	authRequest := auth.PasswordAuthRequest{
		ConnectionAuthPendingMetadata: meta,
		Password:                      base64.StdEncoding.EncodeToString(password),
	}

	_, _, _ = method, authType, authRequest

	return &localClientContext{meta.AuthFailed(), false, nil}
}

func (client *localClient) PubKey(
	meta metadata.ConnectionAuthPendingMetadata,
	pubKey auth.PublicKey,
) AuthenticationContext {
	if !client.enablePubKey {
		err := message.UserMessage(
			message.EAuthDisabled,
			"Public key authentication failed.",
			"Public key authentication is disabled.",
		)
		client.logger.Debug(err)
		return &localClientContext{meta.AuthFailed(), false, err}
	}

	//authRequest := auth.PublicKeyAuthRequest{
	//	ConnectionAuthPendingMetadata: meta,
	//	PublicKey:                     pubKey,
	//}
	//method := "Public key"
	//authType := "pubkey"

	user, err := user.Lookup(meta.Username)
	if err != nil {
		return &localClientContext{meta.AuthFailed(), false, err}
	}

	authorizedKeysBytes, err := os.ReadFile(filepath.Join(user.HomeDir, ".ssh", "authorized_keys"))
	if err != nil {
		return &localClientContext{meta.AuthFailed(), false, err}
	}

	authorizedKeysMap := map[string]bool{}
	for len(authorizedKeysBytes) > 0 {
		userPubKey, _, _, rest, err := ssh.ParseAuthorizedKey(authorizedKeysBytes)
		if err != nil {
			return &localClientContext{meta.AuthFailed(), false, err}
		}

		authorizedKeysMap[string(userPubKey.Marshal())] = true
		authorizedKeysBytes = rest
	}
	reqPubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pubKey.PublicKey))
	if authorizedKeysMap[string(reqPubKey.Marshal())] {
		return &localClientContext{meta.Authenticated(meta.Username), true, nil}
	}

	return &localClientContext{meta.AuthFailed(), false, nil}
}

func (client *localClient) logAttempt(logger log.Logger, method string, lastLabels []metrics.MetricLabel) {
	logger.Debug(
		message.NewMessage(
			message.MAuth,
			"%s authentication request",
			method,
		),
	)
	client.backendRequestsMetric.Increment(lastLabels...)
}

func (client *localClient) logTemporaryFailure(
	logger log.Logger,
	lastError error,
	method string,
	reason string,
	lastLabels []metrics.MetricLabel,
) {
	logger.Debug(
		message.Wrap(
			lastError,
			message.EAuthBackendError,
			"%s authentication request to backend failed, retrying in 10 seconds",
			method,
		).
			Label("reason", reason),
	)
	client.backendFailureMetric.Increment(
		append(
			[]metrics.MetricLabel{
				metrics.Label("type", "soft"),
			}, lastLabels...,
		)...,
	)
}

func (client *localClient) getReason(lastError error) string {
	var typedErr message.Message
	reason := message.EUnknownError
	if errors.As(lastError, &typedErr) {
		reason = typedErr.Code()
	}
	return reason
}

func (client *localClient) logAuthResponse(
	logger log.Logger,
	method string,
	authResponse *auth.ResponseBody,
	labels []metrics.MetricLabel,
	remoteAddr net.IP,
) {
	if authResponse.Success {
		logger.Debug(
			message.NewMessage(
				message.MAuthSuccessful,
				"%s authentication successful",
				method,
			),
		)
		client.authSuccessMetric.Increment(remoteAddr, labels...)
	} else {
		logger.Debug(
			message.NewMessage(
				message.EAuthFailed,
				"%s authentication failed",
				method,
			),
		)
		client.authFailureMetric.Increment(remoteAddr, labels...)
	}
}
