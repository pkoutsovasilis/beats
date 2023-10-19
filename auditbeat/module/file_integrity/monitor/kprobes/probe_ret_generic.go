package kprobes

import "github.com/elastic/beats/v7/auditbeat/module/file_integrity/monitor/tracing"

type KRetProbeGeneric struct {
	Meta      tracing.Metadata `kprobe:"metadata"`
	PID       uint32           `kprobe:"common_pid"`
	Ret       int32            `kprobe:"ret"`
	AddressID uint32
}

func (v *KRetProbeGeneric) SetAddressID(id uint32) {
	v.AddressID = id
}

func (v *KRetProbeGeneric) GetProbeEventKey() ProbeEventKey {
	return ProbeEventKey{
		AddressID: v.AddressID,
		Pid:       v.PID,
		Tid:       v.Meta.TID,
	}
}

func (v *KRetProbeGeneric) ShouldIntercept() bool {
	return v.Ret >= 0
}
