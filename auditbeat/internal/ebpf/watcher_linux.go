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

package ebpf

import (
	"context"
	"fmt"
	"sync"

	"github.com/elastic/ebpfevents"
)

var (
	gWatcherOnce sync.Once
	gWatcherErr  error
	gWatcher     watcher
)

type client struct {
	name   string
	mask   EventMask
	events chan ebpfevents.Event
	errors chan error
}

type watcher struct {
	sync.Mutex
	ctx     context.Context
	cancel  context.CancelFunc
	loader  *ebpfevents.Loader
	clients map[string]client
	status  status
}

type status int

const (
	stopped status = iota
	started
)

func GetWatcher() (Watcher, error) {
	gWatcher.Lock()
	defer gWatcher.Unlock()

	// Try to load the probe once on startup so consumers can error out.
	gWatcherOnce.Do(func() {
		if gWatcher.status == stopped {
			l, err := ebpfevents.NewLoader()
			if err != nil {
				gWatcherErr = fmt.Errorf("init ebpf loader: %w", err)
				return
			}
			_ = l.Close()
		}
	})

	return &gWatcher, gWatcherErr
}

func (w *watcher) Subscribe(name string, events EventMask) (<-chan ebpfevents.Event, <-chan error) {
	w.Lock()
	defer w.Unlock()

	if w.status == stopped {
		startLocked()
	}

	w.clients[name] = client{
		name:   name,
		mask:   events,
		events: make(chan ebpfevents.Event),
		errors: make(chan error),
	}

	return w.clients[name].events, w.clients[name].errors
}

func (w *watcher) Unsubscribe(name string) {
	w.Lock()
	defer w.Unlock()

	delete(w.clients, name)

	if w.nclients() == 0 {
		stopLocked()
	}
}

func startLocked() {
	loader, err := ebpfevents.NewLoader()
	if err != nil {
		gWatcherErr = fmt.Errorf("start ebpf loader: %w", err)
		return
	}

	gWatcher.loader = loader
	gWatcher.clients = make(map[string]client)

	events := make(chan ebpfevents.Event)
	errors := make(chan error)
	gWatcher.ctx, gWatcher.cancel = context.WithCancel(context.Background())

	go gWatcher.loader.EventLoop(gWatcher.ctx, events, errors)
	go func() {
		for {
			select {
			case err := <-errors:
				for _, client := range gWatcher.clients {
					client.errors <- err
				}
				continue
			case ev := <-events:
				for _, client := range gWatcher.clients {
					if client.mask&EventMask(ev.Type) != 0 {
						client.events <- ev
					}
				}
				continue
			case <-gWatcher.ctx.Done():
				return
			}
		}
	}()

	gWatcher.status = started
}

func stopLocked() {
	_ = gWatcher.close()
	gWatcher.status = stopped
}

func (w *watcher) nclients() int {
	return len(w.clients)
}

func (w *watcher) close() error {
	if w.cancel != nil {
		w.cancel()
	}

	if w.loader != nil {
		_ = w.loader.Close()
	}

	for _, cl := range w.clients {
		close(cl.events)
		close(cl.errors)
	}

	return nil
}
