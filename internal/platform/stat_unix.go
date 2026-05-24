//go:build !windows

package platform

import (
	"os"
	"syscall"
)

func populateStatOwnership(meta *FileMeta, info os.FileInfo) {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		meta.UID = st.Uid
		meta.GID = st.Gid
	}
}
