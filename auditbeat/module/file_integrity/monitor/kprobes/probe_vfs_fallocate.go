package kprobes

import (
	"github.com/elastic/beats/v7/auditbeat/module/file_integrity/monitor/tracing"
	"golang.org/x/sys/unix"
)

// int vfs_fallocate(struct file *file, int mode, loff_t offset, loff_t len)

func init() {
	registerKProbe[VFSFAllocate]("vfs_fallocate",
		"file_name=+0(+40(+160($arg1))):string "+
			"parent_ino=+64(+48(+24(+160($arg1)))):u64 "+
			"parent_file_name=+0(+40(+24(+160($arg1)))):string "+
			"parent_parent_ino=+64(+48(+24(+24(+160($arg1))))):u64 "+
			"parent_dev_major=+16(+40(+48(+24(+160($arg1))))):b12@20/32 "+
			"parent_dev_minor=+16(+40(+48(+24(+160($arg1))))):b10@0/32")

	registerKRetProbe[KRetProbeGeneric]("vfs_fallocate")
}

type VFSFAllocate struct {
	Meta             tracing.Metadata `kprobe:"metadata"`
	PID              uint32           `kprobe:"common_pid"`
	ParentParentIno  uint64           `kprobe:"parent_parent_ino"`
	ParentIno        uint64           `kprobe:"parent_ino"`
	ParentDevMajor   uint32           `kprobe:"parent_dev_major"`
	ParentDevMinor   uint32           `kprobe:"parent_dev_minor"`
	FileName         string           `kprobe:"file_name"`
	ParentFileName   string           `kprobe:"parent_file_name"`
	AddressID        uint32
	parentCacheEntry *dirEntryVal
}

func (v *VFSFAllocate) SetAddressID(id uint32) {
	v.AddressID = id
}

func (v *VFSFAllocate) GetProbeEventKey() ProbeEventKey {
	return ProbeEventKey{
		AddressID: v.AddressID,
		Pid:       v.PID,
		Tid:       v.Meta.TID,
	}
}

func (v *VFSFAllocate) ShouldIntercept(dirCache dirEntryCache) bool {
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

func (v *VFSFAllocate) Emit(dirCache dirEntryCache, emitter Emitter) error {
	cacheEntry := &dirEntryVal{
		Parent:    v.parentCacheEntry,
		Children:  nil,
		Name:      v.FileName,
		ParentIno: v.ParentIno,
	}

	v.parentCacheEntry.Children[cacheEntry] = struct{}{}

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

func (v *VFSFAllocate) Assume(dirCache dirEntryCache, emitter Emitter) error {
	return v.Emit(dirCache, emitter)
}
