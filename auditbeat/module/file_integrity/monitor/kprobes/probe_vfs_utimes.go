package kprobes

import (
	"github.com/elastic/beats/v7/auditbeat/module/file_integrity/monitor/tracing"
	"golang.org/x/sys/unix"
)

// int vfs_utimes(const struct path *path, struct timespec64 *times)

func init() {
	registerKProbe[VFSUtimes]("vfs_utimes",
		"file_name=+0(+40(+8($arg1))):string "+
			"parent_ino=+64(+48(+24(+8($arg1)))):u64 "+
			"dev_major=+16(+40(+48(+8($arg1)))):b12@20/32 "+
			"dev_minor=+16(+40(+48(+8($arg1)))):b10@0/32")

	registerKRetProbe[KRetProbeGeneric]("vfs_utimes")
}

type VFSUtimes struct {
	Meta       tracing.Metadata `kprobe:"metadata"`
	PID        uint32           `kprobe:"common_pid"`
	ParentIno  uint64           `kprobe:"parent_ino"`
	FileName   string           `kprobe:"file_name"`
	DevMajor   uint32           `kprobe:"dev_major"`
	DevMinor   uint32           `kprobe:"dev_minor"`
	AddressID  uint32
	cacheEntry *dirEntryVal
}

func (v *VFSUtimes) SetAddressID(id uint32) {
	v.AddressID = id
}

func (v *VFSUtimes) GetProbeEventKey() ProbeEventKey {
	return ProbeEventKey{
		AddressID: v.AddressID,
		Pid:       v.PID,
		Tid:       v.Meta.TID,
	}
}

func (v *VFSUtimes) ShouldIntercept(dirCache dirEntryCache) bool {
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

func (v *VFSUtimes) Emit(dirCache dirEntryCache, emitter Emitter) error {
	return emitter.Emit(FilesystemEvent{
		Type:     EventTypeUpdated,
		FilePath: v.cacheEntry.BuildPath(),
		PID:      v.PID,
	})
}

func (v *VFSUtimes) Assume(dirCache dirEntryCache, emitter Emitter) error {
	return v.Emit(dirCache, emitter)
}
