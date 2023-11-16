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

//go:build linux

package file_integrity

import (
	"path/filepath"
	"strings"
	"time"

	"github.com/elastic/beats/v7/auditbeat/internal/ebpf"
	"github.com/elastic/ebpfevents"
	"github.com/elastic/elastic-agent-libs/logp"
)

const clientName = "fim"

type ebpfReader struct {
	watcher ebpf.Watcher
	done    <-chan struct{}
	config  Config
	log     *logp.Logger
	eventC  chan Event
	parsers []FileParser
	paths   map[string]struct{}

	_events <-chan ebpfevents.Event
	_errors <-chan error
}

func (r *ebpfReader) Start(done <-chan struct{}) (<-chan Event, error) {
	watcher, err := ebpf.GetWatcher()
	if err != nil {
		return nil, err
	}
	r.watcher = watcher
	r.done = done

	mask := ebpf.EventMask(ebpfevents.EventTypeFileCreate | ebpfevents.EventTypeFileRename | ebpfevents.EventTypeFileDelete)
	r._events, r._errors = r.watcher.Subscribe(clientName, mask)

	go r.consumeEvents()

	r.log.Infow("started ebpf watcher", "file_path", r.config.Paths, "recursive", r.config.Recursive)
	return r.eventC, nil
}

func (r *ebpfReader) consumeEvents() {
	defer close(r.eventC)
	defer r.watcher.Unsubscribe(clientName)

	for {
		select {
		case event := <-r._events:
			if event.Type != ebpfevents.EventTypeFileCreate &&
				event.Type != ebpfevents.EventTypeFileRename &&
				event.Type != ebpfevents.EventTypeFileDelete {
				r.log.Warnf("received unwanted ebpf event: %s", event.Type.String())
				continue
			}

			start := time.Now()
			e, ok := NewEventFromEbpfEvent(
				event,
				r.config.MaxFileSizeBytes,
				r.config.HashTypes,
				r.parsers,
				r.excludedPath,
			)
			if !ok {
				r.log.Debugf("skipping excluded path: %s", e.Path)
				continue
			}
			e.rtt = time.Since(start)

			r.log.Debugw("received ebpf event", "file_path", e.Path)
			r.eventC <- e
		case err := <-r._errors:
			r.log.Errorf("ebpf watcher error: %v", err)
		case <-r.done:
			r.log.Debug("ebpf watcher terminated")
			return
		}
	}
}

func (r *ebpfReader) excludedPath(path string) bool {
	dir := filepath.Dir(path)

	if r.config.IsExcludedPath(dir) {
		return true
	}

	if !r.config.Recursive {
		if _, ok := r.paths[dir]; ok {
			return false
		}
	} else {
		for p := range r.paths {
			if strings.HasPrefix(dir, p) {
				return false
			}
		}
	}

	return true
}
