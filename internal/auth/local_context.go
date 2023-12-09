package auth

import (
	"go.containerssh.io/libcontainerssh/metadata"
)

type localClientContext struct {
	meta    metadata.ConnectionAuthenticatedMetadata
	success bool
	err     error
}

func (h localClientContext) AuthenticatedUsername() string {
	return h.meta.AuthenticatedUsername
}

func (h localClientContext) Success() bool {
	return h.success
}

func (h localClientContext) Error() error {
	return h.err
}

func (h localClientContext) Metadata() metadata.ConnectionAuthenticatedMetadata {
	return h.meta
}

func (h localClientContext) OnDisconnect() {
}
