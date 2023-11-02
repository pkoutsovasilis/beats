package kprobes

import (
	"github.com/elastic/beats/v7/auditbeat/module/file_integrity/monitor/tracing"
	"golang.org/x/sys/unix"
)

// ssize_t vfs_write(struct file *file, const char __user *buf, size_t count, loff_t *pos)

func init() {
	registerKProbe[VFSWrite]("vfs_writev",
		"parent_ino=+64(+48(+24(+160($arg1)))):u64 "+
			"file_name=+0(+40(+160($arg1))):string "+
			"dev_major=+16(+40(+48(+24(+160($arg1))))):b12@20/32 "+
			"dev_minor=+16(+40(+48(+24(+160($arg1))))):b10@0/32")

	registerKRetProbe[KRetVFSWrite]("vfs_writev")

	registerKProbe[VFSWrite]("vfs_write",
		"parent_ino=+64(+48(+24(+160($arg1)))):u64 "+
			"file_name=+0(+40(+160($arg1))):string "+
			"dev_major=+16(+40(+48(+24(+160($arg1))))):b12@20/32 "+
			"dev_minor=+16(+40(+48(+24(+160($arg1))))):b10@0/32")

	registerKRetProbe[KRetVFSWrite]("vfs_write")
}

type VFSWrite struct {
	Meta       tracing.Metadata `kprobe:"metadata"`
	PID        uint32           `kprobe:"common_pid"`
	ParentIno  uint64           `kprobe:"parent_ino"`
	FileName   string           `kprobe:"file_name"`
	DevMajor   uint32           `kprobe:"dev_major"`
	DevMinor   uint32           `kprobe:"dev_minor"`
	AddressID  uint32
	cacheEntry *dirEntryVal
}

func (v *VFSWrite) SetAddressID(id uint32) {
	v.AddressID = id
}

func (v *VFSWrite) GetProbeEventKey() ProbeEventKey {
	return ProbeEventKey{
		AddressID: v.AddressID,
		Pid:       v.PID,
		Tid:       v.Meta.TID,
	}
}

func (v *VFSWrite) ShouldIntercept(dirCache dirEntryCache) bool {
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

func (v *VFSWrite) Emit(_ dirEntryCache, emitter Emitter) error {
	return emitter.Emit(FilesystemEvent{
		Type:     EventTypeUpdated,
		FilePath: v.cacheEntry.BuildPath(),
		PID:      v.PID,
	})
}

func (v *VFSWrite) Assume(dirCache dirEntryCache, emitter Emitter) error {
	return v.Emit(dirCache, emitter)
}

type KRetVFSWrite struct {
	Meta         tracing.Metadata `kprobe:"metadata"`
	PID          uint32           `kprobe:"common_pid"`
	Ret          int32            `kprobe:"ret"`
	ProbeAddress uint32
}

func (v *KRetVFSWrite) SetAddressID(id uint32) {
	v.ProbeAddress = id
}

func (v *KRetVFSWrite) GetProbeEventKey() ProbeEventKey {
	return ProbeEventKey{
		AddressID: v.ProbeAddress,
		Pid:       v.PID,
		Tid:       v.Meta.TID,
	}
}

func (v *KRetVFSWrite) ShouldIntercept() bool {
	return v.Ret >= 0
}
