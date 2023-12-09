package config

// LocalConfig is the base configuration structure of the Docker backend.
type LocalConfig struct {
}

// Validate validates the provided configuration and returns an error if invalid.
func (c LocalConfig) Validate() error {
	return nil
}
