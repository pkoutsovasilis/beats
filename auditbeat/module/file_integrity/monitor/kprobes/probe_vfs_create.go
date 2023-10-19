package kprobes

import (
	"github.com/elastic/beats/v7/auditbeat/module/file_integrity/monitor/tracing"
	"golang.org/x/sys/unix"
)

// int vfs_create(struct user_namespace *mnt_userns, struct inode *dir,
//	struct dentry *dentry, umode_t mode, bool want_excl)

func init() {
	registerKProbe[VFSCreate]("vfs_create",
		"file_name=+0(+40($arg3)):string "+
			"parent_ino=+64(+48(+24($arg3))):u64 "+
			"parent_parent_ino=+64(+48(+24(+24($arg3)))):u64 "+
			"parent_file_name=+0(+40(+24($arg3))):string "+
			"parent_dev_major=+16(+40(+48(+24($arg3)))):b12@20/32 "+
			"parent_dev_minor=+16(+40(+48(+24($arg3)))):b10@0/32")

	registerKRetProbe[KRetProbeGeneric]("vfs_create")
}

type VFSCreate struct {
	Meta             tracing.Metadata `kprobe:"metadata"`
	PID              uint32           `kprobe:"common_pid"`
	ParentIno        uint64           `kprobe:"parent_ino"`
	ParentParentIno  uint64           `kprobe:"parent_parent_ino"`
	ParentDevMajor   uint32           `kprobe:"parent_dev_major"`
	ParentDevMinor   uint32           `kprobe:"parent_dev_minor"`
	FileName         string           `kprobe:"file_name"`
	ParentFileName   string           `kprobe:"parent_file_name"`
	AddressID        uint32
	parentCacheEntry *dirEntryVal
}

func (v *VFSCreate) SetAddressID(id uint32) {
	v.AddressID = id
}

func (v *VFSCreate) GetProbeEventKey() ProbeEventKey {
	return ProbeEventKey{
		AddressID: v.AddressID,
		Pid:       v.PID,
		Tid:       v.Meta.TID,
	}
}

func (v *VFSCreate) ShouldIntercept(dirCache dirEntryCache) bool {
	parentCacheEntry, exists := dirCache[dirEntryKey{
		ParentIno: v.ParentParentIno,
		Name:      v.ParentFileName,
		Dev:       unix.Mkdev(v.ParentDevMajor, v.ParentDevMinor),
	}]
	if !exists {
		return false
	}

	v.parentCacheEntry = parentCacheEntry

	return true
}

func (v *VFSCreate) Emit(dirCache dirEntryCache, emitter Emitter) error {
	cacheEntry := &dirEntryVal{
		Parent: v.parentCacheEntry,
		Name:   v.FileName,
	}

	dirCache[dirEntryKey{
		ParentIno: v.ParentIno,
		Name:      v.FileName,
		Dev:       unix.Mkdev(v.ParentDevMajor, v.ParentDevMinor),
	}] = cacheEntry

	return emitter.Emit(FilesystemEvent{
		Type:     EventTypeCreated,
		FilePath: cacheEntry.BuildPath(),
		PID:      v.PID,
	})
}

func (v *VFSCreate) Assume(dirCache dirEntryCache, emitter Emitter) error {
	return v.Emit(dirCache, emitter)
}
