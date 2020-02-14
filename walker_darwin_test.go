package fswalker

import (
	"syscall"
)

func setTimes(st syscall.Stat_t, a, m, c syscall.Timespec) syscall.Stat_t {
	st.Atimespec = a
	st.Mtimespec = m
	st.Ctimespec = c

	return st
}
