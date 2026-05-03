package admin

// Probes is the bundle of read-only state hooks the admin server exposes.
// Each runtime component (dispatcher, dedup, tracker) implements one slice
// of this interface; main.go wires them together. This pattern keeps the
// admin package free of imports on the runtime packages, avoiding cycles
// and making each probe individually mockable for tests.
type Probes struct {
	Dispatch DispatchProbe
	Dedup    DedupProbe
	Tracker  TrackerProbe
}

// DispatchProbe reports per-instance queue depth and capacity. The admin
// server uses this for backpressure detection in /healthz and per-instance
// state in /admin/state.
type DispatchProbe interface {
	QueueState() []QueueState
}

type QueueState struct {
	Instance string `json:"instance"`
	Depth    int    `json:"depth"`
	Capacity int    `json:"capacity"`
}

// DedupProbe exposes the in-memory dedup map size and a clear hook for
// the panic-button admin endpoint after a misconfigured dedup_window.
type DedupProbe interface {
	Size() int
	Clear()
}

// TrackerProbe exposes pending-deliveries count and the most recent N
// finalized deliveries for /admin/deliveries.
type TrackerProbe interface {
	Pending() int
	RecentFinal() []FinalRecord
}

type FinalRecord struct {
	EventID    string            `json:"event_id"`
	State      string            `json:"state"`
	Created    string            `json:"created"`
	Finalized  string            `json:"finalized"`
	Subscribers map[string]string `json:"subscribers"`
}
