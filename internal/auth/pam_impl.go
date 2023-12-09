package auth

import (
	"errors"
	"fmt"
	"net"

	"github.com/tknie/pam"
	"go.containerssh.io/libcontainerssh/config"
	"go.containerssh.io/libcontainerssh/log"
	"go.containerssh.io/libcontainerssh/metadata"
)

type pamAuthContext struct {
	client *pamAuthClient

	connectionId string
	remoteAddr   net.IP

	loginUsername string

	meta    metadata.ConnectionAuthenticatedMetadata
	success bool
	err     error

	transaction *pam.Transaction
}

type pamAuthClient struct {
	logger   log.Logger
	config   config.AuthPAMClientConfig
	authType AuthenticationType
}

func (k pamAuthContext) Success() bool {
	return k.success
}

func (k pamAuthContext) Error() error {
	if !k.success && k.err == nil {
		k.err = fmt.Errorf("an unknown error happened during pam authentication")
	}
	return k.err
}

func (k pamAuthContext) Metadata() metadata.ConnectionAuthenticatedMetadata {
	if k.client == nil {
		return k.meta
	}
	meta := k.meta
	return meta
}

func (k pamAuthContext) OnDisconnect() {
	if k.transaction != nil {
		k.transaction.CloseSession(pam.Silent)
	}
}

func authService(user, passwd string) (*pam.Transaction, error) {
	if passwd == "" {
		return nil, errors.New("the password cannot be empty")
	}
	t, err := pam.StartFunc("sshd", user, func(s pam.Style, msg string) (string, error) {
		switch s {
		case pam.PromptEchoOff:
			return passwd, nil
		case pam.PromptEchoOn:
			return passwd, nil
		case pam.ErrorMsg:
			return "", nil
		case pam.TextInfo:
			return "", nil
		}
		return "", errors.New("Unrecognized message style")
	})
	if err != nil {
		return nil, err
	}
	// 调用 auth 配置
	err = t.Authenticate(pam.Silent)
	if err != nil {
		return nil, err
	}
	// 调用 pam 的 account 配置
	err = t.AcctMgmt(pam.Silent)
	if err != nil {
		return nil, err
	}
	return t, nil
}

func (c *pamAuthClient) Password(
	meta metadata.ConnectionAuthPendingMetadata,
	password []byte,
) AuthenticationContext {
	if c.authType != AuthenticationTypePassword && c.authType != AuthenticationTypeAll {
		return &pamAuthContext{
			meta:    meta.AuthFailed(),
			success: false,
			err:     fmt.Errorf("authentication client not configured for password authentication"),
		}
	}

	transaction, err := authService(meta.Username, string(password))
	if err != nil {
		return pamAuthContext{
			client:  c,
			success: false,
			err:     err,
		}
	}

	ctx := pamAuthContext{
		client:        c,
		loginUsername: meta.Username,
		connectionId:  meta.ConnectionID,
		remoteAddr:    meta.RemoteAddress.IP,
		success:       true,
		err:           nil,
		transaction:   transaction,
	}

	authMeta, err := ctx.AllowLogin(meta.Username, meta)
	if err != nil {
		return pamAuthContext{
			client:  c,
			success: false,
			err:     err,
		}
	}
	authMeta.Metadata["password"] = metadata.Value{
		Value:     string(password),
		Sensitive: true,
	}
	return pamPasswordAuthContext{
		ctx,
		authMeta,
	}
}

type pamPasswordAuthContext struct {
	pamAuthContext

	meta metadata.ConnectionAuthenticatedMetadata
}

func (k *pamAuthContext) DeleteSecContext() error {
	return nil
}

func (k *pamAuthContext) AllowLogin(
	username string,
	meta metadata.ConnectionAuthPendingMetadata,
) (metadata.ConnectionAuthenticatedMetadata, error) {
	if !k.Success() {
		return meta.AuthFailed(), nil
	}

	k.meta = meta.Authenticated(username)
	return k.meta, nil
}
