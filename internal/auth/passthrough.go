package auth

// PamClient is the authenticator for pam-based authentication. It supports plain text authentication.
type PassThroughClient interface {
	PasswordAuthenticator
	PublicKeyAuthenticator
}
