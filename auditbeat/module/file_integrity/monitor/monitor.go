// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package monitor

import (
	"errors"
	"fmt"

	"github.com/fsnotify/fsnotify"
)

const (
	moduleName = "file_integrity"
)

type WatcherAlloc func(recursive bool, IsExcludedPath func(path string) bool) (Watcher, error)

var watcherFactories map[string]WatcherAlloc
var defaultFactory WatcherAlloc

func init() {
	watcherFactories = make(map[string]WatcherAlloc)
}

func Register(isDefault bool, name string, allocFn WatcherAlloc) {
	watcherFactories[name] = allocFn
	if isDefault {
		defaultFactory = allocFn
	}
}

// Watcher is an interface for a file watcher akin to fsnotify.Watcher
// with an additional Start method.
type Watcher interface {
	Add(path string) error
	Close() error
	EventChannel() <-chan fsnotify.Event
	ErrorChannel() <-chan error
	Start() error
}

// New creates a new Watcher backed by fsnotify (default) with optional recursive
// logic.
func New(recursive bool, IsExcludedPath func(path string) bool) (Watcher, error) {
	if defaultFactory == nil {
		return nil, errors.New("no default watcher backend set")
	}

	return defaultFactory(recursive, IsExcludedPath)
}

// NewWithBackend creates a new Watcher backed by fsnotify with optional recursive
// logic.
func NewWithBackend(backendName string, recursive bool, IsExcludedPath func(path string) bool) (Watcher, error) {

	watchFn, exists := watcherFactories[backendName]
	if !exists {
		return nil, fmt.Errorf("backend with name %s not found", backendName)
	}

	return watchFn(recursive, IsExcludedPath)
}
