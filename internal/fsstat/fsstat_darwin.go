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
			Atime:   timespec2Timestamp(stat.Atimespec),
			Mtime:   timespec2Timestamp(stat.Mtimespec),
			Ctime:   timespec2Timestamp(stat.Ctimespec),
		}
	}

	log.Panicf("unexpected info.Sys() type %T for %#v", info.Sys(), info)

	return nil
}

func timespec2Timestamp(s syscall.Timespec) *tspb.Timestamp {
	return &tspb.Timestamp{Seconds: s.Sec, Nanos: int32(s.Nsec)}
}
