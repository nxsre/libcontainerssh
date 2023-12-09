package sshserver

import (
	"context"
	"github.com/gliderlabs/ssh"

	"go.containerssh.io/libcontainerssh/metadata"
)

// HACK: check HACKS.md "OnHandshakeSuccess conformanceTestHandler"
type networkConnectionWrapper struct {
	NetworkConnectionHandler

	authenticatedMetadata metadata.ConnectionAuthenticatedMetadata
	sshConnectionHandler  SSHConnectionHandler
	ctx                   ssh.Context
}

func (n *networkConnectionWrapper) OnShutdown(shutdownContext context.Context) {
	n.sshConnectionHandler.OnShutdown(shutdownContext)
}
