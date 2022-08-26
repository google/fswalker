package fsstat

import (
	"fmt"
	"os"
	"syscall"

	fspb "github.com/google/fswalker/proto/fswalker"
)

// ToStat returns a fspb.ToStat with the file info from the given file
func ToStat(info os.FileInfo) (*fspb.FileStat, error) {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return &fspb.FileStat{
			Dev:     uint64(stat.Dev),
			Inode:   stat.Ino,
			Nlink:   uint64(stat.Nlink),
			Mode:    uint32(stat.Mode),
			Uid:     stat.Uid,
			Gid:     stat.Gid,
			Rdev:    uint64(stat.Rdev),
			Size:    stat.Size,
			Blksize: int64(stat.Blksize),
			Blocks:  stat.Blocks,
			Atime:   timespec2Timestamp(stat.Atim),
			Mtime:   timespec2Timestamp(stat.Mtim),
			Ctime:   timespec2Timestamp(stat.Ctim),
		}, nil
	}

	return nil, fmt.Errorf("unable to get file stat for %#v", info)
}
