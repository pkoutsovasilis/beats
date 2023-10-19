package fsnotify

import (
	"github.com/fsnotify/fsnotify"

	"github.com/elastic/beats/v7/auditbeat/module/file_integrity/monitor"
)

func init() {
	monitor.Register(true, "fsnotify", New)
}

func New(recursive bool, IsExcludedPath func(path string) bool) (monitor.Watcher, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	// Use our simulated recursive watches unless the fsnotify implementation
	// supports OS-provided recursive watches
	if recursive && watcher.SetRecursive() != nil {
		return newRecursiveWatcher(watcher, IsExcludedPath, "file_integrity"), nil
	}
	return (*nonRecursiveWatcher)(watcher), nil
}
