package audit

import (
	"context"
	"sync"
)

// StreamEvent pairs an audit Event with the monotonic sequence number the
// hub assigned it. The sequence is what an SSE client echoes back in the
// Last-Event-ID header on reconnect, so the hub can replay exactly the
// events it missed and nothing else.
type StreamEvent struct {
	Seq   uint64
	Event Event
}

// StreamHub is an [Emitter] that keeps a bounded ring of recent events and
// fans each new one out to live subscribers. It backs the Runtime Monitor
// live stream (GET /v1/admin/audit/stream) without ever touching, or
// slowing, the inline decision path:
//
//   - Emit is non-blocking. It appends to an in-memory ring under a short
//     mutex and does a non-blocking send to each subscriber channel. A
//     subscriber whose buffer is full is skipped for that frame (it can
//     catch up from the ring on reconnect), so a slow browser can never
//     apply backpressure to the gateway. This is the same drop-not-block
//     contract every telemetry sink shares.
//   - Memory is bounded by the ring size regardless of event rate or how
//     many clients connect.
//   - When nobody is connected the hub is just a ring buffer nothing reads.
//
// Safe for concurrent use.
type StreamHub struct {
	mu     sync.Mutex
	seq    uint64
	ring   []StreamEvent
	size   int
	subs   map[int]chan StreamEvent
	nextID int
}

// NewStreamHub returns a hub whose replay ring holds the last ringSize
// events. A non-positive ringSize falls back to a sensible default.
func NewStreamHub(ringSize int) *StreamHub {
	if ringSize <= 0 {
		ringSize = 1024
	}
	return &StreamHub{
		size: ringSize,
		ring: make([]StreamEvent, 0, ringSize),
		subs: make(map[int]chan StreamEvent),
	}
}

// Emit assigns the next sequence number, records the event in the ring, and
// broadcasts it to every subscriber without blocking. It satisfies
// [Emitter], so the hub can sit in the audit fan-out beside the store and
// the SIEM sinks.
func (h *StreamHub) Emit(_ context.Context, e Event) {
	if h == nil {
		return
	}
	h.mu.Lock()
	h.seq++
	se := StreamEvent{Seq: h.seq, Event: e}
	if len(h.ring) >= h.size {
		// Ring is full: shift left by one and append. size is small, so the
		// copy is cheap and keeps the slice a simple oldest-to-newest window.
		copy(h.ring, h.ring[1:])
		h.ring[len(h.ring)-1] = se
	} else {
		h.ring = append(h.ring, se)
	}
	for _, ch := range h.subs {
		select {
		case ch <- se:
		default:
			// Subscriber buffer full: drop this frame for that client. It
			// will resync from the ring using Last-Event-ID when it
			// reconnects, so no decision is silently lost end to end.
		}
	}
	h.mu.Unlock()
}

// Subscribe registers a live subscriber. It returns, atomically under one
// lock: the ring events with a sequence strictly greater than afterSeq (the
// Last-Event-ID replay; pass 0 to replay the whole ring), a channel that
// delivers every subsequent event, and a cancel func the caller MUST invoke
// (defer it) to unregister and release the channel.
//
// buffer sizes the per-subscriber channel; a non-positive value uses a
// default. A larger buffer tolerates a briefly slow client before frames
// start dropping.
func (h *StreamHub) Subscribe(afterSeq uint64, buffer int) (replay []StreamEvent, ch <-chan StreamEvent, cancel func()) {
	if buffer <= 0 {
		buffer = 256
	}
	c := make(chan StreamEvent, buffer)
	h.mu.Lock()
	for _, se := range h.ring {
		if se.Seq > afterSeq {
			replay = append(replay, se)
		}
	}
	id := h.nextID
	h.nextID++
	h.subs[id] = c
	h.mu.Unlock()

	var once sync.Once
	cancel = func() {
		once.Do(func() {
			h.mu.Lock()
			if cc, ok := h.subs[id]; ok {
				delete(h.subs, id)
				close(cc)
			}
			h.mu.Unlock()
		})
	}
	return replay, c, cancel
}

// LastSeq reports the sequence number of the most recent event, or 0 if
// none has been emitted. Useful for a client that wants to start "from now"
// rather than replaying the ring.
func (h *StreamHub) LastSeq() uint64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.seq
}
