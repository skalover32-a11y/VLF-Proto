package store

import (
	"fmt"
	"sync"
	"time"
)

type wheelEntry struct {
	key      string
	slot     int
	rounds   int
	callback func()
}

type Wheel struct {
	interval time.Duration
	slots    []map[string]*wheelEntry
	entries  map[string]*wheelEntry
	cursor   int

	mu     sync.Mutex
	stopCh chan struct{}
	wg     sync.WaitGroup
}

func NewWheel(interval time.Duration, slotCount int) *Wheel {
	if interval <= 0 {
		interval = time.Second
	}
	if slotCount < 4 {
		slotCount = 4
	}

	w := &Wheel{
		interval: interval,
		slots:    make([]map[string]*wheelEntry, slotCount),
		entries:  make(map[string]*wheelEntry),
		stopCh:   make(chan struct{}),
	}
	for i := range w.slots {
		w.slots[i] = make(map[string]*wheelEntry)
	}

	w.wg.Add(1)
	go w.run()
	return w
}

func (w *Wheel) run() {
	defer w.wg.Done()

	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			w.tick()
		case <-w.stopCh:
			return
		}
	}
}

func (w *Wheel) tick() {
	var callbacks []func()

	w.mu.Lock()
	w.cursor = (w.cursor + 1) % len(w.slots)
	slot := w.slots[w.cursor]

	for key, entry := range slot {
		if entry.rounds > 0 {
			entry.rounds--
			continue
		}

		delete(slot, key)
		delete(w.entries, key)
		if entry.callback != nil {
			callbacks = append(callbacks, entry.callback)
		}
	}
	w.mu.Unlock()

	for _, cb := range callbacks {
		cb()
	}
}

func (w *Wheel) Upsert(key string, ttl time.Duration, callback func()) {
	if ttl <= 0 {
		ttl = w.interval
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	w.removeLocked(key)

	steps := int(ttl / w.interval)
	if ttl%w.interval != 0 {
		steps++
	}
	if steps < 1 {
		steps = 1
	}

	slotCount := len(w.slots)
	targetSlot := (w.cursor + steps) % slotCount
	rounds := steps / slotCount
	if targetSlot <= w.cursor {
		rounds--
	}
	if rounds < 0 {
		rounds = 0
	}

	entry := &wheelEntry{
		key:      key,
		slot:     targetSlot,
		rounds:   rounds,
		callback: callback,
	}

	w.entries[key] = entry
	w.slots[targetSlot][key] = entry
}

func (w *Wheel) Touch(key string, ttl time.Duration) bool {
	if ttl <= 0 {
		ttl = w.interval
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	entry, ok := w.entries[key]
	if !ok {
		return false
	}

	callback := entry.callback
	w.removeLocked(key)

	steps := int(ttl / w.interval)
	if ttl%w.interval != 0 {
		steps++
	}
	if steps < 1 {
		steps = 1
	}

	slotCount := len(w.slots)
	targetSlot := (w.cursor + steps) % slotCount
	rounds := steps / slotCount
	if targetSlot <= w.cursor {
		rounds--
	}
	if rounds < 0 {
		rounds = 0
	}

	next := &wheelEntry{
		key:      key,
		slot:     targetSlot,
		rounds:   rounds,
		callback: callback,
	}
	w.entries[key] = next
	w.slots[targetSlot][key] = next
	return true
}

func (w *Wheel) Remove(key string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.removeLocked(key)
}

func (w *Wheel) removeLocked(key string) {
	entry, ok := w.entries[key]
	if !ok {
		return
	}
	delete(w.slots[entry.slot], key)
	delete(w.entries, key)
}

func (w *Wheel) Close() {
	close(w.stopCh)
	w.wg.Wait()
}

func RelayKey(connID string) string {
	return "relay:" + connID
}

func SessionKey(sessionID uint64) string {
	return fmt.Sprintf("session:%d", sessionID)
}
