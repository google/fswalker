// Copyright 2018 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package fswalker contains functionality to walk a file system and compare the differences.
package fswalker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"github.com/golang/protobuf/proto"
)

// Generating Go representations for the proto buf libraries.

//go:generate protoc -I=. -I=$GOPATH/src --go_out=paths=source_relative:. proto/fswalker/fswalker.proto

const (
	// tsFileFormat is the time format used in file names.
	tsFileFormat = "20060102-150405"
)

// WalkFilename returns the appropriate filename for a Walk for the given host and time.
// If time is not provided, it returns a file pattern to glob by.
func WalkFilename(hostname string, t time.Time) string {
	hn := "*"
	if hostname != "" {
		hn = hostname
	}
	ts := "*"
	if !t.IsZero() {
		ts = t.Format(tsFileFormat)
	}
	return fmt.Sprintf("%s-%s-fswalker-state.pb", hn, ts)
}

// sha256sum reads the given file path and builds a SHA-256 sum over its content.
func sha256sum(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// readTextProto reads a text format proto buf and unmarshals it into the provided proto message.
func readTextProto(ctx context.Context, path string, pb proto.Message) error {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}
	return proto.UnmarshalText(string(b), pb)
}

// writeTextProto writes a text format proto buf for the provided proto message.
func writeTextProto(ctx context.Context, path string, pb proto.Message) error {
	blob := proto.MarshalTextString(pb)
	// replace message boundary characters as curly braces look nicer (both is fine to parse)
	blob = strings.Replace(strings.Replace(blob, "<", "{", -1), ">", "}", -1)
	return ioutil.WriteFile(path, []byte(blob), 0644)
}
