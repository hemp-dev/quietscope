//go:build windows

package platform

import "os"

func populateStatOwnership(meta *FileMeta, info os.FileInfo) {
	meta.UID = 0
	meta.GID = 0
}
