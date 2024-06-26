package structutils

import "dario.cat/mergo"

// Merge copies non-default values from source to destination
func Merge(destination interface{}, source interface{}) error {
	return mergo.Merge(destination, source, mergo.WithOverride)
}
