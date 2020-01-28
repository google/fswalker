package fsstat

import (
	"fmt"
	"os"
	"syscall"
)

// DevNumber returns the device number for info
func DevNumber(info os.FileInfo) (uint64, error) {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return uint64(stat.Dev), nil
	}

	return 0, fmt.Errorf("unable to get file stat for %#v", info)
}
