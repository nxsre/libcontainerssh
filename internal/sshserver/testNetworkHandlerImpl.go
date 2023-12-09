package sshserver

import (
	"context"
	"github.com/gliderlabs/ssh"
	"net"

	"go.containerssh.io/libcontainerssh/metadata"
)

type testNetworkHandlerImpl struct {
	AbstractNetworkConnectionHandler

	rootHandler  *testHandlerImpl
	client       net.TCPAddr
	connectionID string
	shutdown     bool
}

func (t *testNetworkHandlerImpl) OnHandshakeSuccess(meta metadata.ConnectionAuthenticatedMetadata, ctx ssh.Context) (SSHConnectionHandler, metadata.ConnectionAuthenticatedMetadata, error) {
	return &testSSHHandler{
		rootHandler:    t.rootHandler,
		networkHandler: t,
		metadata:       meta,
		ctx:            ctx,
	}, meta, nil
}

func (t *testNetworkHandlerImpl) OnShutdown(_ context.Context) {
	t.shutdown = true
}

func (t *testNetworkHandlerImpl) Context() ssh.Context {
	return t.rootHandler.Context()
}
