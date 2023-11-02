package kprobes

import (
	"github.com/elastic/beats/v7/auditbeat/module/file_integrity/monitor/tracing"
	"golang.org/x/sys/unix"
)

//static int do_open(struct nameidata *nd,
//		   struct file *file, const struct open_flags *op)

func init() {
	registerKProbeWithFilter[VFSOpen]("do_open",
		"parent_ino=+64(+48(+24(+8($arg1)))):u64 "+
			"created=+20($arg2):b1@20/64 "+
			"file_name=+0(+40(+8($arg1))):string "+
			"parent_dev_major=+16(+40(+48(+24(+8($arg1))))):b12@20/32 "+
			"parent_dev_minor=+16(+40(+48(+24(+8($arg1))))):b10@0/32 "+
			"parent_file_name=+0(+40(+24(+8($arg1)))):string "+
			"parent_parent_ino=+64(+48(+24(+24(+8($arg1))))):u64",
		"created == 1")

	registerKRetProbe[KRetProbeGeneric]("do_open")
}

type VFSOpen struct {
	Meta            tracing.Metadata `kprobe:"metadata"`
	PID             uint32           `kprobe:"common_pid"`
	ParentIno       uint64           `kprobe:"parent_ino"`
	ParentDevMajor  uint32           `kprobe:"parent_dev_major"`
	ParentDevMinor  uint32           `kprobe:"parent_dev_minor"`
	FileName        string           `kprobe:"file_name"`
	ParentFileName  string           `kprobe:"parent_file_name"`
	ParentParentIno uint64           `kprobe:"parent_parent_ino"`
	AddressID       uint32
	ParentEntry     *dirEntryVal
}

func (v *VFSOpen) SetAddressID(id uint32) {
	v.AddressID = id
}

func (v *VFSOpen) GetProbeEventKey() ProbeEventKey {
	return ProbeEventKey{
		AddressID: v.AddressID,
		Pid:       v.PID,
		Tid:       v.Meta.TID,
	}
}

func (v *VFSOpen) ShouldIntercept(dirCache dirEntryCache) bool {

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

func (v *VFSOpen) Emit(dirCache dirEntryCache, emitter Emitter) error {
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

func (v *VFSOpen) Assume(dirCache dirEntryCache, emitter Emitter) error {
	return v.Emit(dirCache, emitter)
}
