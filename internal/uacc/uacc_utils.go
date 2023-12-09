/*
Copyright 2021 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package uacc

import (
	"encoding/binary"
	"net"
	"os"
	"strings"

	"github.com/gravitational/trace"
)

// PrepareAddr parses and transforms a net.Addr into a format usable by other uacc functions.
func PrepareAddr(addr net.Addr) ([4]int32, error) {
	stringIP, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return [4]int32{}, trace.Wrap(err)
	}
	ip := net.ParseIP(stringIP)
	rawV6 := ip.To16()

	// this case can occur if the net.Addr isn't in an expected IP format, in that case, ignore it
	// we have to guard against this because the net.Addr internal format is implementation specific
	if rawV6 == nil {
		return [4]int32{}, nil
	}

	groupedV6 := [4]int32{}
	for i := range groupedV6 {
		// some bit magic to convert the byte array into 4 32 bit integers
		groupedV6[i] = int32(binary.LittleEndian.Uint32(rawV6[i*4 : (i+1)*4]))
	}
	return groupedV6, nil
}

// FileExists checks whether a file exists at a given path
func FileExists(fp string) bool {
	_, err := os.Stat(fp)
	if err != nil && os.IsNotExist(err) {
		return false
	}
	return true
}

// return remote client hostname or IP if host lookup fails
// addr is expected to be of the format given by net.Addr.String()
// eg., "127.0.0.1:80" or "[::1]:80"
func GetHost(addr string) (h string) {
	if !strings.Contains(addr, "[") {
		h = strings.Split(addr, ":")[0]
	} else {
		h = strings.Split(strings.Split(addr, "[")[1], "]")[0]
	}
	hList, e := net.LookupAddr(h)
	//fmt.Printf("lookupAddr:%v\n", hList)
	if e == nil {
		h = hList[0]
	}
	return
}
