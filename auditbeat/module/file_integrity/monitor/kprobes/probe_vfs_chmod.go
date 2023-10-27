package kprobes

import (
	"github.com/elastic/beats/v7/auditbeat/module/file_integrity/monitor/tracing"
	"golang.org/x/sys/unix"
)

// int chmod_common(const struct path *path, umode_t mode)

func init() {

	registerKRetProbe[KRetProbeGeneric]("chmod_common")
	registerKProbe[VFSChmod]("chmod_common",
		"parent_ino=+64(+48(+24(+8($arg1)))):u64 "+
			"file_name=+0(+40(+8($arg1))):string "+
			"dev_major=+16(+40(+48(+8($arg1)))):b12@20/32 "+
			"dev_minor=+16(+40(+48(+8($arg1)))):b10@0/32")
}

type VFSChmod struct {
	Meta       tracing.Metadata `kprobe:"metadata"`
	PID        uint32           `kprobe:"common_pid"`
	ParentIno  uint64           `kprobe:"parent_ino"`
	FileName   string           `kprobe:"file_name"`
	DevMajor   uint32           `kprobe:"dev_major"`
	DevMinor   uint32           `kprobe:"dev_minor"`
	AddressID  uint32
	cacheEntry *dirEntryVal
}

func (v *VFSChmod) SetAddressID(id uint32) {
	v.AddressID = id
}

func (v *VFSChmod) GetProbeEventKey() ProbeEventKey {
	return ProbeEventKey{
		AddressID: v.AddressID,
		Pid:       v.PID,
		Tid:       v.Meta.TID,
	}
}

func (v *VFSChmod) ShouldIntercept(dirCache dirEntryCache) bool {
	cacheEntry, exists := dirCache[dirEntryKey{
		ParentIno: v.ParentIno,
		Name:      v.FileName,
		Dev:       unix.Mkdev(v.DevMajor, v.DevMinor),
	}]
	if !exists {
		return false
	}

	v.cacheEntry = cacheEntry

	return true
}

func (v *VFSChmod) Emit(_ dirEntryCache, emitter Emitter) error {
	return emitter.Emit(FilesystemEvent{
		Type:     EventTypeChmod,
		FilePath: v.cacheEntry.BuildPath(),
		PID:      v.PID,
	})
}

func (v *VFSChmod) Assume(dirCache dirEntryCache, emitter Emitter) error {
	return v.Emit(dirCache, emitter)
}
