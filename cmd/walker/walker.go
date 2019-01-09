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

// Walker is a CLI tool to walk over a set of directories and process all discovered files.
package main

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/google/fswalker"

	fspb "github.com/google/fswalker/proto/fswalker"
)

var (
	maxHashFileSize = flag.Int64("maxHashFileSize", 1024*1024, "max size of a file in bytes up to which a hash is generated")
	policyFile      = flag.String("policyFile", "", "required policy file to use")
	outputFilePfx   = flag.String("outputFilePfx", "", "path prefix for the output file to write (when a path is set)")
	verbose         = flag.Bool("verbose", false, "when set to true, prints all discovered files including a metadata summary")
)

func walkCallback(walk *fspb.Walk) error {
	if *outputFilePfx == "" {
		return nil
	}
	outpath, err := outputPath(*outputFilePfx)
	if err != nil {
		return err
	}
	walkBytes, err := proto.Marshal(walk)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(outpath, walkBytes, 0444)
}

func outputPath(pfx string) (string, error) {
	hn, err := os.Hostname()
	if err != nil {
		return "", fmt.Errorf("unable to determine hostname: %v", err)
	}
	return filepath.Join(pfx, fswalker.WalkFilename(hn, time.Now())), nil
}

func main() {
	ctx := context.Background()
	flag.Parse()

	if *policyFile == "" {
		log.Fatal("policyFile needs to be specified")
	}

	w, err := fswalker.WalkerFromPolicyFile(ctx, *policyFile)
	if err != nil {
		log.Fatal(err)
	}
	w.Verbose = *verbose
	w.WalkCallback = walkCallback

	// Walk the file system and wait for completion of processing.
	if err := w.Run(ctx); err != nil {
		log.Fatal(err)
	}

	fmt.Println("Metrics:")
	for _, k := range w.Counter.Metrics() {
		v, _ := w.Counter.Get(k)
		fmt.Printf("[%-30s] = %6d\n", k, v)
	}
}
