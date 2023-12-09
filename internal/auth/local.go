// This file contains the details of the localClient authenticator

package auth

// LocalClient is a client that authenticates using localClient pam or pubkey. It only supports password and public key
// authentication.
type LocalClient interface {
	PasswordAuthenticator
	PublicKeyAuthenticator
}
