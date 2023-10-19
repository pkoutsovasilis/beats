package kprobes

import (
	"github.com/elastic/beats/v7/auditbeat/module/file_integrity/monitor/tracing"
	"golang.org/x/sys/unix"
)

// int vfs_rmdir(struct user_namespace *mnt_userns, struct inode *dir,
// 	struct dentry *dentry)

func init() {
	registerKProbe[VFSRmdir]("vfs_rmdir",
		"parent_ino=+64(+48(+24($arg3))):u64 "+
			"file_name=+0(+40($arg3)):string "+
			"dev_major=+16(+40(+48($arg3))):b12@20/32 "+
			"dev_minor=+16(+40(+48($arg3))):b10@0/32")

	registerKRetProbe[KRetProbeGeneric]("vfs_rmdir")
}

type VFSRmdir struct {
	Meta       tracing.Metadata `kprobe:"metadata"`
	PID        uint32           `kprobe:"common_pid"`
	ParentIno  uint64           `kprobe:"parent_ino"`
	FileName   string           `kprobe:"file_name"`
	DevMajor   uint32           `kprobe:"dev_major"`
	DevMinor   uint32           `kprobe:"dev_minor"`
	AddressID  uint32
	cacheEntry *dirEntryVal
}

func (v *VFSRmdir) SetAddressID(id uint32) {
	v.AddressID = id
}

func (v *VFSRmdir) GetProbeEventKey() ProbeEventKey {
	return ProbeEventKey{
		AddressID: v.AddressID,
		Pid:       v.PID,
		Tid:       v.Meta.TID,
	}
}

func (v *VFSRmdir) ShouldIntercept(dirCache dirEntryCache) bool {
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

func (v *VFSRmdir) Emit(dirCache dirEntryCache, emitter Emitter) error {

	delete(dirCache, dirEntryKey{
		ParentIno: v.ParentIno,
		Dev:       unix.Mkdev(v.DevMajor, v.DevMinor),
		Name:      v.FileName,
	})

	return emitter.Emit(FilesystemEvent{
		Type:     EventTypeDeleted,
		FilePath: v.cacheEntry.BuildPath(),
		PID:      v.PID,
	})
}

func (v *VFSRmdir) Assume(dirCache dirEntryCache, emitter Emitter) error {
	return v.Emit(dirCache, emitter)
}
