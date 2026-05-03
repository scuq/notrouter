package event

import (
	"net"
	"time"
)

type Urgency string

const (
	UrgencyInfo     Urgency = "info"
	UrgencyLow      Urgency = "low"
	UrgencyMedium   Urgency = "medium"
	UrgencyHigh     Urgency = "high"
	UrgencyCritical Urgency = "critical"
)

type Event struct {
	ID         string
	Source     string
	Entity     string
	EntityIP   net.IP
	Topic      string
	Urgency    Urgency
	Timestamp  time.Time
	Attributes map[string]string
	Raw        []byte
}

func New(source string, raw []byte) *Event {
	return &Event{
		Source:     source,
		Timestamp:  time.Now().UTC(),
		Attributes: make(map[string]string),
		Raw:        raw,
	}
}
