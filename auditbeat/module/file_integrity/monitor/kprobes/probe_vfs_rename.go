package kprobes

import (
	"github.com/elastic/beats/v7/auditbeat/module/file_integrity/monitor/tracing"
	"golang.org/x/sys/unix"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// int vfs_rename(struct renamedata *)

func init() {
	registerKProbe[VFSRename]("vfs_rename",
		"src_parent_ino=+64(+48(+24(+16($arg1)))):s64 "+
			"src_file_name=+0(+40(+16($arg1))):string "+
			"src_file_mode=+0(+48(+24(+16($arg1)))):u16 "+
			"src_dev_major=+16(+40(+48(+16($arg1)))):b12@20/32 "+
			"src_dev_minor=+16(+40(+48(+16($arg1)))):b10@0/32 "+
			"dst_parent_ino=+64(+48(+24(+40($arg1)))):u64 "+
			"dst_file_name=+0(+40(+40($arg1))):string "+
			"dst_parent_parent_ino=+64(+48(+24(+24(+40($arg1))))):u64 "+
			"dst_parent_file_name=+0(+40(+24(+40($arg1)))):string "+
			"parent_dest_dev_major=+16(+40(+48(+24(+40($arg1))))):b12@20/32 "+
			"parent_dest_dev_minor=+16(+40(+48(+24(+40($arg1))))):b10@0/32")

	registerKRetProbe[KRetProbeGeneric]("vfs_rename")
}

type VFSRename struct {
	Meta                tracing.Metadata `kprobe:"metadata"`
	PID                 uint32           `kprobe:"common_pid"`
	SrcParentIno        uint64           `kprobe:"src_parent_ino"`
	SrcFileName         string           `kprobe:"src_file_name"`
	SrcFileMode         uint16           `kprobe:"src_file_mode"`
	SrcDevMajor         uint32           `kprobe:"src_dev_major"`
	SrcDevMinor         uint32           `kprobe:"src_dev_minor"`
	DestParentIno       uint64           `kprobe:"dst_parent_ino"`
	DestFileName        string           `kprobe:"dst_file_name"`
	DestParentParentIno uint64           `kprobe:"dst_parent_parent_ino"`
	DestParentFileName  string           `kprobe:"dst_parent_file_name"`
	DestParentDevMajor  uint32           `kprobe:"parent_dest_dev_major"`
	DestParentDevMinor  uint32           `kprobe:"parent_dest_dev_minor"`
	AddressID           uint32
	srcCacheEntry       *dirEntryVal
	dstParentCacheEntry *dirEntryVal
}

func (v *VFSRename) SetAddressID(id uint32) {
	v.AddressID = id
}

func (v *VFSRename) GetProbeEventKey() ProbeEventKey {
	return ProbeEventKey{
		AddressID: v.AddressID,
		Pid:       v.PID,
		Tid:       v.Meta.TID,
	}
}

func (v *VFSRename) ShouldIntercept(dirCache dirEntryCache) bool {
	srcCacheEntry, srcExists := dirCache[dirEntryKey{
		ParentIno: v.SrcParentIno,
		Name:      v.SrcFileName,
		Dev:       unix.Mkdev(v.SrcDevMajor, v.SrcDevMinor),
	}]

	dstParentCacheEntry, destExists := dirCache[dirEntryKey{
		ParentIno: v.DestParentParentIno,
		Name:      v.DestParentFileName,
		Dev:       unix.Mkdev(v.DestParentDevMajor, v.DestParentDevMinor),
	}]

	srcDiffDestinationDiff := v.SrcDevMinor != v.DestParentDevMinor || v.SrcDevMajor != v.DestParentDevMajor
	if srcDiffDestinationDiff {
		return false
	}

	if !srcExists && !destExists {
		return false
	}

	v.srcCacheEntry = srcCacheEntry
	v.dstParentCacheEntry = dstParentCacheEntry

	return true
}

func (v *VFSRename) Emit(dirCache dirEntryCache, emitter Emitter) error {

	oldPath := v.srcCacheEntry.BuildPath()

	if v.dstParentCacheEntry == nil {

		// destination outside our monitoring paths
		dirCache.WipeWithChildren(v.srcCacheEntry, unix.Mkdev(v.SrcDevMajor, v.SrcDevMinor))

		err := emitter.Emit(FilesystemEvent{
			Type:     EventTypeMoved,
			FilePath: oldPath,
			PID:      v.PID,
		})

		if err != nil {
			return err
		}

		return nil
	}

	if v.srcCacheEntry == nil {
		// src outside out monitoring paths
		isSrcDir := (v.SrcFileMode & 00170000) == 0040000

		cacheEntry := &dirEntryVal{
			Parent: v.dstParentCacheEntry,
			Name:   v.DestFileName,
		}

		dirCache[dirEntryKey{
			ParentIno: v.DestParentIno,
			Name:      v.DestFileName,
			Dev:       unix.Mkdev(v.DestParentDevMajor, v.DestParentDevMinor),
		}] = cacheEntry

		fileDir := cacheEntry.BuildPath()

		err := emitter.Emit(FilesystemEvent{
			Type:     EventTypeCreated,
			FilePath: fileDir,
			PID:      v.PID,
		})
		if err != nil {
			return err
		}

		if !isSrcDir {
			// this file is not a directory so no need to proceed
			return nil
		}

		cacheEntry.Children = make(dirEntryChildren)

		// here we need to go to the filesystem and walk recursively
		// all the content of the dir that just moved in
		var createdPaths []string
		cacheEntriesByPath := make(map[string]*dirEntryVal)
		cacheEntriesByPath[fileDir] = cacheEntry

		rootInoChecked := false
		_ = filepath.WalkDir(fileDir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}

			if path == fileDir {
				parentDir := filepath.Dir(path)
				parentDirEntryInfo, err := os.Lstat(parentDir)
				if err != nil {
					return nil
				}

				rootInoChecked = parentDirEntryInfo.Sys().(*syscall.Stat_t).Ino == v.DestParentIno
				return nil
			}

			if !rootInoChecked {
				return nil
			}

			parentDir := filepath.Dir(path)
			parentDirEntryInfo, err := os.Lstat(parentDir)
			if err != nil {
				return nil
			}

			parentCacheEntry, exists := cacheEntriesByPath[parentDir]
			if !exists {
				return nil
			}

			cacheEntry = &dirEntryVal{
				Parent:    parentCacheEntry,
				Children:  nil,
				Name:      filepath.Base(path),
				ParentIno: parentDirEntryInfo.Sys().(*syscall.Stat_t).Ino,
			}

			if d.IsDir() {
				cacheEntry.Children = make(dirEntryChildren)
			}

			parentCacheEntry.Children[cacheEntry] = struct{}{}

			cacheEntriesByPath[path] = cacheEntry
			dirCache[dirEntryKey{
				ParentIno: parentDirEntryInfo.Sys().(*syscall.Stat_t).Ino,
				Name:      filepath.Base(path),
				Dev:       unix.Mkdev(v.DestParentDevMajor, v.DestParentDevMinor),
			}] = cacheEntry

			createdPaths = append(createdPaths, path)
			return nil
		})

		for _, path := range createdPaths {
			if err := emitter.Emit(FilesystemEvent{
				Type:     EventTypeCreated,
				FilePath: path,
				PID:      v.PID,
			}); err != nil {
				return err
			}
		}
		return nil
	}

	// both src and dest inside the same filesystem and our monitoring paths
	// so we soft "delete" the old entry from parent and map, and we attach it
	// to new parent with new map entry
	delete(v.srcCacheEntry.Parent.Children, v.srcCacheEntry)
	delete(dirCache, dirEntryKey{
		ParentIno: v.SrcParentIno,
		Name:      v.SrcFileName,
		Dev:       unix.Mkdev(v.SrcDevMajor, v.SrcDevMinor),
	})

	err := emitter.Emit(FilesystemEvent{
		Type:     EventTypeMoved,
		FilePath: oldPath,
		PID:      v.PID,
	})
	if err != nil {
		return err
	}

	v.srcCacheEntry.Parent = v.dstParentCacheEntry
	v.srcCacheEntry.Name = v.DestFileName
	v.dstParentCacheEntry.Children[v.srcCacheEntry] = struct{}{}

	dirCache[dirEntryKey{
		ParentIno: v.DestParentIno,
		Name:      v.DestFileName,
		Dev:       unix.Mkdev(v.DestParentDevMajor, v.DestParentDevMinor),
	}] = v.srcCacheEntry

	dirCache.WalkEntry(v.srcCacheEntry, func(path string) {
		_ = emitter.Emit(FilesystemEvent{
			Type:     EventTypeCreated,
			FilePath: path,
			PID:      v.PID,
		})
	})

	return nil
}

func (v *VFSRename) Assume(dirCache dirEntryCache, emitter Emitter) error {
	return v.Emit(dirCache, emitter)
}
