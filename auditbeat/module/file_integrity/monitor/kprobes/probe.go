package kprobes

import (
	"github.com/elastic/beats/v7/auditbeat/module/file_integrity/monitor/tracing"
	"sync"
)

type ProbeEventKey struct {
	AddressID uint32
	Pid       uint32
	Tid       uint32
}

type Emitter interface {
	Emit(event FilesystemEvent) error
}

type KProbeAddress interface {
	SetAddressID(id uint32)
}

type KProbe interface {
	KProbeAddress
	GetProbeEventKey() ProbeEventKey
	ShouldIntercept(dirCache dirEntryCache) bool
	Emit(dirCache dirEntryCache, emitter Emitter) error
	Assume(dirCache dirEntryCache, emitter Emitter) error
}

type KRetProbe interface {
	KProbeAddress
	GetProbeEventKey() ProbeEventKey
	ShouldIntercept() bool
}

type kProbeHolder struct {
	probe   tracing.Probe
	allocFn func() interface{}
}

func (k *kProbeHolder) startProbe(tfs *tracing.TraceFS, perfChannel *tracing.PerfChannel) error {
	if k == nil {
		return nil
	}

	err := tfs.AddKProbe(k.probe)
	if err != nil {
		return err
	}
	desc, err := tfs.LoadProbeFormat(k.probe)
	if err != nil {
		return err
	}

	decoder, err := tracing.NewStructDecoder(desc, k.allocFn)
	if err != nil {
		return err
	}

	if err := perfChannel.MonitorProbe(desc, decoder); err != nil {
		return err
	}

	return nil
}

type addressKProbes struct {
	id          uint32
	entryProbe  *kProbeHolder
	returnProbe *kProbeHolder
}

var kProbes map[string]*addressKProbes
var probeEventCache map[ProbeEventKey]KProbe
var mtx sync.Mutex

func init() {
	kProbes = make(map[string]*addressKProbes)
	probeEventCache = make(map[ProbeEventKey]KProbe)
}

func registerKProbe[T any, PT interface {
	*T
	KProbe
}](symbolName string, fetchArgs string) {
	mtx.Lock()
	defer mtx.Unlock()

	probeDefinition := tracing.Probe{
		Type:      tracing.TypeKProbe,
		Group:     "filebeat",
		Name:      "kprobe_" + symbolName,
		Address:   symbolName,
		Fetchargs: fetchArgs,
		Filter:    "",
	}
	probeRegister[T, PT](probeDefinition)
}

func registerKProbeWithFilter[T any, PT interface {
	*T
	KProbe
}](address string, fetchArgs string, filter string) {
	mtx.Lock()
	defer mtx.Unlock()

	probeDefinition := tracing.Probe{
		Type:      tracing.TypeKProbe,
		Name:      "kprobe_" + address,
		Address:   address,
		Fetchargs: fetchArgs,
		Filter:    filter,
	}

	probeRegister[T, PT](probeDefinition)
}

func registerKRetProbe[T any, PT interface {
	*T
	KRetProbe
}](address string) {
	mtx.Lock()
	defer mtx.Unlock()

	probeDefinition := tracing.Probe{
		Type:      tracing.TypeKRetProbe,
		Name:      "kretprobe_" + address,
		Address:   address,
		Fetchargs: "ret=$retval:s32",
	}

	probeRegister[T, PT](probeDefinition)
}

func probeRegister[T any, PT interface {
	*T
	KProbeAddress
}](probe tracing.Probe) {
	holder, exists := kProbes[probe.Address]
	if !exists {
		id := uint32(len(kProbes))
		holder = &addressKProbes{
			id:          id,
			entryProbe:  nil,
			returnProbe: nil,
		}
		kProbes[probe.Address] = holder
	}

	kprobeAddressId := holder.id

	allocFn := func() interface{} {
		t := new(T)
		pt := PT(t)
		pt.SetAddressID(kprobeAddressId)
		return pt
	}

	switch probe.Type {
	case tracing.TypeKProbe:
		holder.entryProbe = &kProbeHolder{
			probe:   probe,
			allocFn: allocFn,
		}
	case tracing.TypeKRetProbe:
		holder.returnProbe = &kProbeHolder{
			probe:   probe,
			allocFn: allocFn,
		}
	}
}
