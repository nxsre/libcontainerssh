package local

import (
	"bufio"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
)

// An Entry contains all the fields for a specific user
type Entry struct {
	Pass  string
	Uid   int
	Gid   int
	Gecos string
	Home  string
	Shell string
}

// Parse opens the '/etc/passwd' file and parses it into a map from usernames
// to Entries
func Parse() (map[string]Entry, error) {
	return ParseFile("/etc/passwd")
}

// ParseFile opens the file and parses it into a map from usernames to Entries
func ParseFile(path string) (map[string]Entry, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	defer file.Close()

	return ParseReader(file)
}

// ParseReader consumes the contents of r and parses it into a map from
// usernames to Entries
func ParseReader(r io.Reader) (map[string]Entry, error) {
	lines := bufio.NewReader(r)
	entries := make(map[string]Entry)
	for {
		line, _, err := lines.ReadLine()
		if err != nil {
			break
		}
		name, entry, err := parseLine(string(copyBytes(line)))
		if err != nil {
			return nil, err
		}
		entries[name] = entry
	}
	return entries, nil
}

func parseLine(line string) (string, Entry, error) {
	fs := strings.Split(line, ":")
	if len(fs) != 7 {
		return "", Entry{}, errors.New("Unexpected number of fields in /etc/passwd")
	}
	uid, _ := strconv.Atoi(fs[2])
	gid, _ := strconv.Atoi(fs[3])
	return fs[0], Entry{fs[1], uid, gid, fs[4], fs[5], fs[6]}, nil
}

func copyBytes(x []byte) []byte {
	y := make([]byte, len(x))
	copy(y, x)
	return y
}
