package kprobes

import (
	"github.com/elastic/beats/v7/auditbeat/module/file_integrity/monitor/tracing"
	"golang.org/x/sys/unix"
)

// int vfs_fileattr_set(struct user_namespace *mnt_userns, struct dentry *dentry,
//	struct fileattr *fa)

func init() {
	registerKProbe[VFSSetAttribute]("vfs_fileattr_set",
		"parent_ino=+64(+48(+24($arg2))):u64 "+
			"file_name=+0(+40($arg2)):string "+
			"dev_major=+16(+40(+48($arg2))):b12@20/32 "+
			"dev_minor=+16(+40(+48($arg2))):b10@0/32")

	registerKRetProbe[KRetProbeGeneric]("vfs_fileattr_set")
}

type VFSSetAttribute struct {
	Meta       tracing.Metadata `kprobe:"metadata"`
	PID        uint32           `kprobe:"common_pid"`
	ParentIno  uint64           `kprobe:"parent_ino"`
	FileName   string           `kprobe:"file_name"`
	DevMajor   uint32           `kprobe:"dev_major"`
	DevMinor   uint32           `kprobe:"dev_minor"`
	AddressID  uint32
	cacheEntry *dirEntryVal
}

func (v *VFSSetAttribute) SetAddressID(id uint32) {
	v.AddressID = id
}

func (v *VFSSetAttribute) GetProbeEventKey() ProbeEventKey {
	return ProbeEventKey{
		AddressID: v.AddressID,
		Pid:       v.PID,
		Tid:       v.Meta.TID,
	}
}

func (v *VFSSetAttribute) ShouldIntercept(dirCache dirEntryCache) bool {
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

func (v *VFSSetAttribute) Emit(_ dirEntryCache, emitter Emitter) error {
	return emitter.Emit(FilesystemEvent{
		Type:     EventTypeAttr,
		FilePath: v.cacheEntry.BuildPath(),
		PID:      v.PID,
	})
}

func (v *VFSSetAttribute) Assume(dirCache dirEntryCache, emitter Emitter) error {
	return v.Emit(dirCache, emitter)
}
