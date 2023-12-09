package auth

import (
	"fmt"
	"go.containerssh.io/libcontainerssh/auth"
	"go.containerssh.io/libcontainerssh/message"
	"net"

	"go.containerssh.io/libcontainerssh/config"
	"go.containerssh.io/libcontainerssh/log"
	"go.containerssh.io/libcontainerssh/metadata"
)

type passthroughAuthContext struct {
	client *passthroughAuthClient

	connectionId string
	remoteAddr   net.IP

	loginUsername string

	meta    metadata.ConnectionAuthenticatedMetadata
	success bool
	err     error
}

type passthroughAuthClient struct {
	logger         log.Logger
	config         config.AuthPassThroughClientConfig
	authType       AuthenticationType
	enablePubKey   bool
	enablePassword bool
}

func (k passthroughAuthContext) Success() bool {
	return k.success
}

func (k passthroughAuthContext) Error() error {
	if !k.success && k.err == nil {
		k.err = fmt.Errorf("an unknown error happened during pam authentication")
	}
	return k.err
}

func (k passthroughAuthContext) Metadata() metadata.ConnectionAuthenticatedMetadata {
	if k.client == nil {
		return k.meta
	}
	meta := k.meta
	return meta
}

func (k passthroughAuthContext) OnDisconnect() {
}

func (k *passthroughAuthContext) DeleteSecContext() error {
	return nil
}

func (k *passthroughAuthContext) AllowLogin(
	username string,
	meta metadata.ConnectionAuthPendingMetadata,
) (metadata.ConnectionAuthenticatedMetadata, error) {
	if !k.Success() {
		return meta.AuthFailed(), nil
	}

	k.meta = meta.Authenticated(username)
	return k.meta, nil
}

func (c *passthroughAuthClient) Password(
	meta metadata.ConnectionAuthPendingMetadata,
	password []byte,
) AuthenticationContext {
	if c.authType != AuthenticationTypePassword && c.authType != AuthenticationTypeAll {
		return &passthroughAuthContext{
			meta:    meta.AuthFailed(),
			success: false,
			err:     fmt.Errorf("authentication client not configured for password authentication"),
		}
	}

	meta.Metadata["password"] = metadata.Value{
		Value:     string(password),
		Sensitive: true,
	}

	return &passthroughAuthContext{
		client:        c,
		connectionId:  meta.ConnectionID,
		loginUsername: meta.Username,
		meta: metadata.ConnectionAuthenticatedMetadata{
			ConnectionAuthPendingMetadata: meta,
			AuthenticatedUsername:         meta.Username,
		},
		success: true,
	}
}

func (client *passthroughAuthClient) PubKey(
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
		return &passthroughAuthContext{
			client:        client,
			connectionId:  meta.ConnectionID,
			loginUsername: meta.Username,
			meta:          metadata.ConnectionAuthenticatedMetadata{},
			success:       false,
			err:           err,
		}
	}
	meta.Metadata["pubKey"] = metadata.Value{
		Value:     pubKey.PublicKey,
		Sensitive: true,
	}

	return &passthroughAuthContext{
		client:        client,
		connectionId:  meta.ConnectionID,
		loginUsername: meta.Username,
		meta: metadata.ConnectionAuthenticatedMetadata{
			ConnectionAuthPendingMetadata: meta,
			AuthenticatedUsername:         meta.Username,
		},
		success: true,
	}
}
