package kprobes

import (
	"errors"
	"fmt"
	"github.com/elastic/beats/v7/auditbeat/module/file_integrity/monitor/tracing"
	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/go-perf"
	"github.com/fsnotify/fsnotify"
	"time"

	"github.com/elastic/beats/v7/auditbeat/module/file_integrity/monitor"
)

func init() {
	monitor.Register(false, "kprobes", New)
}

type watch struct {
	eventC      chan fsnotify.Event
	done        chan bool
	perfChannel *tracing.PerfChannel
	addC        chan string
	errC        chan error
	log         *logp.Logger
	traceFS     *tracing.TraceFS

	isExcludedPath func(path string) bool
}

func New(_ bool, IsExcludedPath func(path string) bool) (monitor.Watcher, error) {

	traceFS, err := tracing.NewTraceFS()
	if err != nil {
		return nil, err
	}

	if err := traceFS.RemoveAllKProbes(); err != nil {
		return nil, err
	}

	return &watch{
		eventC:         make(chan fsnotify.Event, 1),
		done:           nil,
		perfChannel:    nil,
		addC:           make(chan string),
		errC:           make(chan error),
		log:            logp.NewLogger("file_integrity"),
		traceFS:        traceFS,
		isExcludedPath: IsExcludedPath,
	}, nil
}

func (w *watch) Emit(event FilesystemEvent) error {

	var ev fsnotify.Event
	switch event.Type {
	case EventTypeInvalid:
		return errors.New("invalid event type")
	case EventTypeCreated:
		ev = fsnotify.Event{
			Name: event.FilePath,
			Op:   fsnotify.Create,
		}
	case EventTypeUpdated:
		ev = fsnotify.Event{
			Name: event.FilePath,
			Op:   fsnotify.Write,
		}
	case EventTypeDeleted:
		ev = fsnotify.Event{
			Name: event.FilePath,
			Op:   fsnotify.Remove,
		}
	case EventTypeMoved:
		ev = fsnotify.Event{
			Name: event.FilePath,
			Op:   fsnotify.Rename,
		}
	case EventTypeChown, EventTypeAttr, EventTypeXAttr, EventTypeChmod:
		ev = fsnotify.Event{
			Name: event.FilePath,
			Op:   fsnotify.Chmod,
		}
	}

	for {
		select {
		case <-w.done:
			return nil

		case path := <-w.addC:
			return dirCache.WalkDir(path, true, w.isExcludedPath)

		case w.eventC <- ev:
			return nil
		}
	}
}

func (w *watch) Add(path string) error {
	if w.done != nil {
		w.addC <- path
		return <-w.errC
	}
	return dirCache.WalkDir(path, true, w.isExcludedPath)
}

func (w *watch) Close() error {
	close(w.eventC)
	return w.perfChannel.Close()
}

func (w *watch) EventChannel() <-chan fsnotify.Event {
	return w.eventC
}

func (w *watch) ErrorChannel() <-chan error {
	return w.errC
}

func (w *watch) Start() error {
	w.done = make(chan bool, 1)

	channel, err := tracing.NewPerfChannel(
		tracing.WithTimestamp(),
		tracing.WithRingSizeExponent(10),
		tracing.WithBufferSize(4096),
		tracing.WithTID(perf.AllThreads),
		tracing.WithPollTimeout(100*time.Millisecond),
	)
	if err != nil {
		return err
	}

	for _, probeHolder := range kProbes {

		if err := probeHolder.entryProbe.startProbe(w.traceFS, channel); err != nil {
			return err
		}

		if err := probeHolder.returnProbe.startProbe(w.traceFS, channel); err != nil {
			return err
		}

	}

	if err := channel.Run(); err != nil {
		return err
	}

	go func() {
		defer func() {
			closeErr := w.Close()
			if closeErr != nil {
				w.log.Warnf("error at closing watcher: %v", closeErr)
			}
		}()

		for {
			select {
			case <-w.done:
				return

			case path := <-w.addC:
				w.errC <- dirCache.WalkDir(path, true, w.isExcludedPath)

			case event, ok := <-channel.C():
				if !ok {
					w.errC <- fmt.Errorf("read invalid event from perf channel")
					return
				}

				switch eventWithType := event.(type) {
				case KProbe:
					shouldIntercept := eventWithType.ShouldIntercept(dirCache)
					if !shouldIntercept {
						continue
					}

					key := eventWithType.GetProbeEventKey()

					existingKProbe, exists := probeEventCache[key]
					if exists {
						w.log.Warnf("kretprobe missed")
						if err = existingKProbe.Assume(dirCache, w); err != nil {
							w.errC <- err
							return
						}
					}
					probeEventCache[key] = eventWithType
				case KRetProbe:
					probeEventKey := eventWithType.GetProbeEventKey()
					probeEvent, exists := probeEventCache[probeEventKey]
					if !exists {
						continue
					}

					delete(probeEventCache, probeEventKey)

					if !eventWithType.ShouldIntercept() {
						continue
					}

					if err = probeEvent.Emit(dirCache, w); err != nil {
						w.errC <- err
						return
					}
				default:
					err = errors.New("unknown event type")
					w.errC <- err
					return
				}

			case err := <-channel.ErrC():
				w.errC <- err
				return

			case lost := <-channel.LostC():
				err = fmt.Errorf("events lost %d", lost)
				w.errC <- err
				return
			}
		}
	}()

	return nil
}
