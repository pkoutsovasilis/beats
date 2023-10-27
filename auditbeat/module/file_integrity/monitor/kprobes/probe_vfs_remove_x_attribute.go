package kprobes

import (
	"github.com/elastic/beats/v7/auditbeat/module/file_integrity/monitor/tracing"
	"golang.org/x/sys/unix"
)

// int vfs_removexattr(struct user_namespace *mnt_userns, struct dentry *dentry,
//	const char *name)

func init() {
	registerKProbe[VFSRemoveXAttribute]("vfs_removexattr",
		"file_name=+0(+40($arg2)):string "+
			"parent_ino=+64(+48(+24($arg2))):u64 "+
			"dev_major=+16(+40(+48($arg2))):b12@20/32 "+
			"dev_minor=+16(+40(+48($arg2))):b10@0/32")

	registerKRetProbe[KRetProbeGeneric]("vfs_removexattr")
}

type VFSRemoveXAttribute struct {
	Meta       tracing.Metadata `kprobe:"metadata"`
	PID        uint32           `kprobe:"common_pid"`
	ParentIno  uint64           `kprobe:"parent_ino"`
	FileName   string           `kprobe:"file_name"`
	DevMajor   uint32           `kprobe:"dev_major"`
	DevMinor   uint32           `kprobe:"dev_minor"`
	AddressID  uint32
	cacheEntry *dirEntryVal
}

func (v *VFSRemoveXAttribute) SetAddressID(id uint32) {
	v.AddressID = id
}

func (v *VFSRemoveXAttribute) GetProbeEventKey() ProbeEventKey {
	return ProbeEventKey{
		AddressID: v.AddressID,
		Pid:       v.PID,
		Tid:       v.Meta.TID,
	}
}

func (v *VFSRemoveXAttribute) ShouldIntercept(dirCache dirEntryCache) bool {
	cacheEntry, exists := dirCache[dirEntryKey{
		ParentIno: v.ParentIno,
		Dev:       unix.Mkdev(v.DevMajor, v.DevMinor),
		Name:      v.FileName,
	}]
	if !exists {
		return false
	}

	v.cacheEntry = cacheEntry

	return true
}

func (v *VFSRemoveXAttribute) Emit(_ dirEntryCache, emitter Emitter) error {

	return emitter.Emit(FilesystemEvent{
		Type:     EventTypeXAttr,
		FilePath: v.cacheEntry.BuildPath(),
		PID:      v.PID,
	})
}

func (v *VFSRemoveXAttribute) Assume(dirCache dirEntryCache, emitter Emitter) error {
	return v.Emit(dirCache, emitter)
}
