package fsstat

import (
	"log"
	"os"
	"syscall"

	tspb "github.com/golang/protobuf/ptypes/timestamp"

	fspb "github.com/google/fswalker/proto/fswalker"
)

// ToStat returns a fspb.ToStat with the file info from the given file
func ToStat(info os.FileInfo) *fspb.FileStat {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return &fspb.FileStat{
			Dev:     stat.Dev,
			Inode:   stat.Ino,
			Nlink:   stat.Nlink,
			Mode:    stat.Mode,
			Uid:     stat.Uid,
			Gid:     stat.Gid,
			Rdev:    stat.Rdev,
			Size:    stat.Size,
			Blksize: stat.Blksize,
			Blocks:  stat.Blocks,
			Atime: &tspb.Timestamp{
				Seconds: stat.Atim.Sec,
				Nanos:   int32(stat.Atim.Nsec),
			},
			Mtime: &tspb.Timestamp{
				Seconds: stat.Mtim.Sec,
				Nanos:   int32(stat.Mtim.Nsec),
			},
			Ctime: &tspb.Timestamp{
				Seconds: stat.Ctim.Sec,
				Nanos:   int32(stat.Ctim.Nsec),
			},
		}
	}

	log.Panicf("unexpected info.Sys() type %T for %#v", info.Sys(), info)

	return nil
}
