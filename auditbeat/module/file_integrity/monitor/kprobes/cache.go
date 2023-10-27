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

type dirEntryChildren map[*dirEntryVal]struct{}

type dirEntryVal struct {
	Parent    *dirEntryVal
	Children  dirEntryChildren
	Name      string
	ParentIno uint64
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

func wipeRecursive(c dirEntryCache, val *dirEntryVal, dev uint64) {
	if val.Children == nil || len(val.Children) == 0 {
		delete(c, dirEntryKey{
			ParentIno: val.ParentIno,
			Dev:       dev,
			Name:      val.Name,
		})
		return
	}

	for child := range val.Children {
		wipeRecursive(c, child, dev)
	}

	delete(c, dirEntryKey{
		ParentIno: val.ParentIno,
		Dev:       dev,
		Name:      val.Name,
	})
}

func walkChildrenRecursive(c dirEntryCache, rootPath string, joinPath bool, val *dirEntryVal, call func(path string)) {
	var path string
	if joinPath {
		path = filepath.Join(rootPath, val.Name)
	} else {
		path = rootPath
	}

	if val.Children == nil || len(val.Children) == 0 {
		call(path)
		return
	}

	for child := range val.Children {
		walkChildrenRecursive(c, path, true, child, call)
	}

	call(path)
}

func (c dirEntryCache) WipeWithChildren(val *dirEntryVal, dev uint64) {
	wipeRecursive(c, val, dev)
}

func (c dirEntryCache) WalkEntry(val *dirEntryVal, call func(path string)) {
	walkChildrenRecursive(c, val.BuildPath(), false, val, call)
}

func (c dirEntryCache) WalkDir(dirPath string, fullRootPath bool, IsExcludedPath func(path string) bool) error {
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

			cacheEntry := &dirEntryVal{
				Parent:    nil,
				Name:      filename,
				Children:  make(dirEntryChildren),
				ParentIno: dirEntryInfo.Sys().(*syscall.Stat_t).Ino,
			}

			if dirEntryInfo.IsDir() {
				cacheEntry.Children = make(dirEntryChildren)
			}

			c[dirEntryKey{
				ParentIno: dirEntryInfo.Sys().(*syscall.Stat_t).Ino,
				Name:      mount.Subtree,
				Dev:       uint64(mount.DeviceNumber),
			}] = cacheEntry
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

			cacheEntry := &dirEntryVal{
				Parent:    parentCacheVal,
				Name:      filename,
				Children:  nil,
				ParentIno: parentDirEntryInfo.Sys().(*syscall.Stat_t).Ino,
			}

			if dirEntryInfo.IsDir() {
				cacheEntry.Children = make(dirEntryChildren)
			}

			if parentCacheVal != nil {
				parentCacheVal.Children[cacheEntry] = struct{}{}
			}

			c[dirEntryKey{
				ParentIno: parentDirEntryInfo.Sys().(*syscall.Stat_t).Ino,
				Name:      filepath.Base(path),
				Dev:       uint64(mount.DeviceNumber),
			}] = cacheEntry
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

		cacheEntry := &dirEntryVal{
			Parent:    parentCacheEntry,
			Name:      filename,
			Children:  nil,
			ParentIno: parentDirEntryInfo.Sys().(*syscall.Stat_t).Ino,
		}

		if dirEntryInfo.IsDir() {
			cacheEntry.Children = make(dirEntryChildren)
		}

		if parentCacheEntry != nil {
			parentCacheEntry.Children[cacheEntry] = struct{}{}
		}

		c[dirEntryKey{
			ParentIno: parentDirEntryInfo.Sys().(*syscall.Stat_t).Ino,
			Name:      filepath.Base(path),
			Dev:       uint64(mount.DeviceNumber),
		}] = cacheEntry

		return nil

	})

	return err

}
