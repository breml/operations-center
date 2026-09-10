package provisioning

import (
	"time"
)

// SeedImageProgress reports how much of its installation media one deployment
// has read.
type SeedImageProgress struct {
	DeploymentID string
	Size         int64
	BytesServed  int64
	BytesCovered int64
	FirstRead    time.Time
	LastRead     time.Time
	RequestCount int
}

// IdleFor returns for how long nothing has been read anymore. It returns 0, if
// nothing has been read at all.
func (p SeedImageProgress) IdleFor(now time.Time) time.Duration {
	if p.LastRead.IsZero() {
		return 0
	}

	return now.Sub(p.LastRead)
}
