// Package fsstat provides access to platform specific file stat info.
package fsstat

import (
	"fmt"
	"os"
	"syscall"

	"google.golang.org/protobuf/types/known/timestamppb"
)

// DevNumber returns the device number for info
func DevNumber(info os.FileInfo) (uint64, error) {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return uint64(stat.Dev), nil
	}

	return 0, fmt.Errorf("unable to get file stat for %#v", info)
}

func timespec2Timestamp(s syscall.Timespec) *timestamppb.Timestamp {
	return &timestamppb.Timestamp{Seconds: s.Sec, Nanos: int32(s.Nsec)}
}
