package kprobes

import (
	"github.com/elastic/beats/v7/auditbeat/module/file_integrity/monitor/tracing"
	"golang.org/x/sys/unix"
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
		delete(dirCache, dirEntryKey{
			ParentIno: v.SrcParentIno,
			Name:      v.SrcFileName,
			Dev:       unix.Mkdev(v.SrcDevMajor, v.SrcDevMinor),
		})

		err := emitter.Emit(FilesystemEvent{
			Type:     EventTypeDeleted,
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

		if isSrcDir {
			path := cacheEntry.BuildPath()
			// TODO(panos) emit events from walking dir
			_ = dirCache.WalkDir(path, false, false, nil)
		}

		return emitter.Emit(FilesystemEvent{
			Type:     EventTypeCreated,
			FilePath: cacheEntry.BuildPath(),
			PID:      v.PID,
		})
	}

	// both src and dest inside the same filesystem and our monitoring paths

	delete(dirCache, dirEntryKey{
		ParentIno: v.SrcParentIno,
		Name:      v.SrcFileName,
		Dev:       unix.Mkdev(v.SrcDevMajor, v.SrcDevMinor),
	})

	err := emitter.Emit(FilesystemEvent{
		Type:     EventTypeDeleted,
		FilePath: oldPath,
		PID:      v.PID,
	})

	if err != nil {
		return err
	}

	v.srcCacheEntry.Parent = v.dstParentCacheEntry

	dirCache[dirEntryKey{
		ParentIno: v.DestParentIno,
		Name:      v.DestFileName,
		Dev:       unix.Mkdev(v.DestParentDevMajor, v.DestParentDevMinor),
	}] = v.srcCacheEntry

	return emitter.Emit(FilesystemEvent{
		Type:     EventTypeCreated,
		FilePath: v.srcCacheEntry.BuildPath(),
		PID:      v.PID,
	})
}

func (v *VFSRename) Assume(dirCache dirEntryCache, emitter Emitter) error {
	return v.Emit(dirCache, emitter)
}
