package kprobes

import (
	"fmt"
	"github.com/elastic/beats/v7/auditbeat/module/file_integrity/monitor/kprobes/filesystem"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"syscall"
)

type dirEntryKey struct {
	ParentIno uint64
	Dev       uint64
	Name      string
}

type dirEntryVal struct {
	Parent *dirEntryVal
	Name   string
}

func (d *dirEntryVal) BuildPath() string {
	var pathTokens []string
	startEntry := d
	for startEntry != nil {
		pathTokens = append(pathTokens, startEntry.Name)
		startEntry = startEntry.Parent
	}
	slices.Reverse(pathTokens)
	finalPath := filepath.Join(pathTokens...)
	return finalPath
}

type dirEntryCache map[dirEntryKey]*dirEntryVal

var dirCache dirEntryCache

func init() {
	dirCache = make(dirEntryCache)
}

func (c dirEntryCache) WalkDir(dirPath string, fullRootPath bool, followSymLinks bool, IsExcludedPath func(path string) bool) error {
	if c == nil {
		return fmt.Errorf("nil map")
	}

	mount, err := filesystem.FindMount(dirPath)
	if err != nil {
		return err
	}

	err = filepath.WalkDir(dirPath, func(path string, d fs.DirEntry, err error) error {

		if d == nil {
			return nil
		}

		if IsExcludedPath != nil && IsExcludedPath(path) {
			return nil
		}

		dirEntryInfo, err := d.Info()
		if err != nil {
			return err
		}

		if path == mount.Path {
			var filename string
			if fullRootPath && path == dirPath {
				filename = dirPath
			} else {
				filename = filepath.Base(path)
			}

			c[dirEntryKey{
				ParentIno: dirEntryInfo.Sys().(*syscall.Stat_t).Ino,
				Name:      mount.Subtree,
				Dev:       uint64(mount.DeviceNumber),
			}] = &dirEntryVal{
				Parent: nil,
				Name:   filename,
			}
			return nil
		}

		parentDir := filepath.Dir(path)
		parentDirEntryInfo, err := os.Lstat(parentDir)
		if err != nil {
			return err
		}

		if parentDir == mount.Path {
			parentCacheVal, exists := c[dirEntryKey{
				ParentIno: parentDirEntryInfo.Sys().(*syscall.Stat_t).Ino,
				Name:      mount.Subtree,
				Dev:       uint64(mount.DeviceNumber),
			}]
			if !exists {
				parentCacheVal = nil
			}

			var filename string
			if fullRootPath && path == dirPath {
				filename = dirPath
			} else {
				filename = filepath.Base(path)
			}

			c[dirEntryKey{
				ParentIno: parentDirEntryInfo.Sys().(*syscall.Stat_t).Ino,
				Name:      filepath.Base(path),
				Dev:       uint64(mount.DeviceNumber),
			}] = &dirEntryVal{
				Parent: parentCacheVal,
				Name:   filename,
			}
			return nil
		}

		parentParentDir := filepath.Dir(parentDir)
		parentParentDirEntryInfo, err := os.Lstat(parentParentDir)
		if err != nil {
			return err
		}

		parentParentDirEntrySysStat := parentParentDirEntryInfo.Sys().(*syscall.Stat_t)
		parentCacheEntry, ok := c[dirEntryKey{
			ParentIno: parentParentDirEntrySysStat.Ino,
			Name:      filepath.Base(parentDir),
			Dev:       uint64(mount.DeviceNumber),
		}]
		if !ok {
			parentCacheEntry = nil
		}

		var filename string
		if fullRootPath && path == dirPath {
			filename = dirPath
		} else {
			filename = filepath.Base(path)
		}

		c[dirEntryKey{
			ParentIno: parentDirEntryInfo.Sys().(*syscall.Stat_t).Ino,
			Name:      filepath.Base(path),
			Dev:       uint64(mount.DeviceNumber),
		}] = &dirEntryVal{
			Parent: parentCacheEntry,
			Name:   filename,
		}

		return nil

	})

	return err

}
