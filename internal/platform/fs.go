package platform

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type FileMeta struct {
	Path    string
	Mode    fs.FileMode
	Size    int64
	ModTime time.Time
	UID     uint32
	GID     uint32
}

type LargeFile struct {
	Path string
	Size int64
}

func StatMeta(path string) (FileMeta, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return FileMeta{}, err
	}
	meta := FileMeta{Path: path, Mode: info.Mode(), Size: info.Size(), ModTime: info.ModTime()}
	populateStatOwnership(&meta, info)
	return meta, nil
}

func FormatPerm(mode fs.FileMode) string {
	return mode.Perm().String()
}

func IsWorldWritable(mode fs.FileMode) bool {
	return mode.Perm()&0002 != 0
}

func IsGroupWritable(mode fs.FileMode) bool {
	return mode.Perm()&0020 != 0
}

func DirectorySize(root string, home string) (int64, error) {
	var total int64
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if ShouldExcludePath(path, home) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		info, statErr := d.Info()
		if statErr != nil {
			return nil
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil
		}
		if !info.IsDir() {
			total += info.Size()
		}
		return nil
	})
	return total, err
}

func FindLargeFiles(root string, home string, minSize int64, limit int) ([]LargeFile, error) {
	var files []LargeFile
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if ShouldExcludePath(path, home) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		info, statErr := d.Info()
		if statErr != nil || info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil
		}
		if info.Size() >= minSize {
			files = append(files, LargeFile{Path: path, Size: info.Size()})
		}
		return nil
	})
	sort.Slice(files, func(i, j int) bool { return files[i].Size > files[j].Size })
	if limit > 0 && len(files) > limit {
		files = files[:limit]
	}
	return files, err
}

func ShouldExcludePath(path string, home string) bool {
	clean := filepath.Clean(path)
	exclusions := []string{
		filepath.Join(home, "Library", "Keychains"),
		filepath.Join(home, "Library", "Mail"),
		filepath.Join(home, "Library", "Messages"),
		filepath.Join(home, "Library", "Containers", "com.apple.mail"),
		filepath.Join(home, "Library", "Group Containers", "group.com.apple.notes"),
		filepath.Join(home, "Library", "Safari"),
		filepath.Join(home, "Library", "Application Support", "Google", "Chrome"),
		filepath.Join(home, "Library", "Application Support", "Firefox"),
		filepath.Join(home, "Library", "Application Support", "BraveSoftware"),
		filepath.Join(home, "Library", "Application Support", "Microsoft Edge"),
		filepath.Join(home, "Pictures", "Photos Library.photoslibrary"),
		filepath.Join(home, "Library", "Mobile Documents"),
		"/System/Volumes/Data/System",
		"/System",
		"/private/var/db",
		"/private/var/folders",
	}
	for _, excluded := range exclusions {
		if excluded == "" {
			continue
		}
		excluded = filepath.Clean(excluded)
		if clean == excluded || strings.HasPrefix(clean, excluded+string(os.PathSeparator)) {
			return true
		}
	}
	return false
}

func HumanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

func ListImmediateChildren(root string) ([]string, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	paths := make([]string, 0, len(entries))
	for _, entry := range entries {
		paths = append(paths, filepath.Join(root, entry.Name()))
	}
	return paths, nil
}
