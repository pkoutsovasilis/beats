package kprobes

import (
	"github.com/elastic/beats/v7/auditbeat/module/file_integrity/monitor/tracing"
	"golang.org/x/sys/unix"
)

// int vfs_link(struct dentry *old_dentry, struct user_namespace *mnt_userns,
// 	struct inode *dir, struct dentry *new_dentry,
// 	struct inode **delegated_inode)

func init() {
	registerKProbe[VFSLink]("vfs_link",
		"parent_ino=+64(+48(+24($arg4))):u64 "+
			"parent_parent_ino=+64(+48(+24(+24($arg4)))):u64 "+
			"parent_file_name=+0(+40(+24($arg4))):string "+
			"parent_dev_major=+16(+40(+48(+24($arg4)))):b12@20/32 "+
			"parent_dev_minor=+16(+40(+48(+24($arg4)))):b10@0/32 "+
			"file_name=+0(+40($arg1)):string")

	registerKRetProbe[KRetProbeGeneric]("vfs_link")
}

type VFSLink struct {
	Meta            tracing.Metadata `kprobe:"metadata"`
	PID             uint32           `kprobe:"common_pid"`
	ParentIno       uint64           `kprobe:"parent_ino"`
	ParentParentIno uint64           `kprobe:"parent_parent_ino"`
	ParentDevMajor  uint32           `kprobe:"parent_dev_major"`
	ParentDevMinor  uint32           `kprobe:"parent_dev_minor"`
	FileName        string           `kprobe:"file_name"`
	ParentFileName  string           `kprobe:"parent_file_name"`
	AddressID       uint32
	ParentEntry     *dirEntryVal
}

func (v *VFSLink) SetAddressID(id uint32) {
	v.AddressID = id
}

func (v *VFSLink) GetProbeEventKey() ProbeEventKey {
	return ProbeEventKey{
		AddressID: v.AddressID,
		Pid:       v.PID,
		Tid:       v.Meta.TID,
	}
}

func (v *VFSLink) ShouldIntercept(dirCache dirEntryCache) bool {
	parentEntry, exists := dirCache[dirEntryKey{
		ParentIno: v.ParentParentIno,
		Dev:       unix.Mkdev(v.ParentDevMajor, v.ParentDevMinor),
		Name:      v.ParentFileName,
	}]
	if !exists {
		return false
	}

	v.ParentEntry = parentEntry

	return true
}

func (v *VFSLink) Emit(dirCache dirEntryCache, emitter Emitter) error {
	cacheEntry := &dirEntryVal{
		Parent:    v.ParentEntry,
		Children:  nil,
		Name:      v.FileName,
		ParentIno: v.ParentIno,
	}

	v.ParentEntry.Children[cacheEntry] = struct{}{}

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

func (v *VFSLink) Assume(dirCache dirEntryCache, emitter Emitter) error {
	return v.Emit(dirCache, emitter)
}
