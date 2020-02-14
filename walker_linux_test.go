package fswalker

import (
	"syscall"
)

func setTimes(st syscall.Stat_t, a, m, c syscall.Timespec) syscall.Stat_t {
	st.Atim = a
	st.Mtim = m
	st.Ctim = c

	return st
}
