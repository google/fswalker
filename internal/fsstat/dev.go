// Package fsstat provides access to platform specific file stat info.
package fsstat

import (
	"fmt"
	"os"
	"syscall"

	tspb "github.com/golang/protobuf/ptypes/timestamp"
)

// DevNumber returns the device number for info
func DevNumber(info os.FileInfo) (uint64, error) {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return uint64(stat.Dev), nil
	}

	return 0, fmt.Errorf("unable to get file stat for %#v", info)
}

func timespec2Timestamp(s syscall.Timespec) *tspb.Timestamp {
	return &tspb.Timestamp{Seconds: s.Sec, Nanos: int32(s.Nsec)}
}
