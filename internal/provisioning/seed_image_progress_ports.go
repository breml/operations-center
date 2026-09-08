package provisioning

import (
	"context"
	"io"
)

// SeedImageProgressPort records how much of its installation media a deployment
// has read.
type SeedImageProgressPort interface {
	// Track wraps content, so that the reads served from it are recorded as
	// progress of the deployment named by deploymentID.
	Track(ctx context.Context, deploymentID string, info SeedImageInfo, content io.ReadSeekCloser) io.ReadSeekCloser

	// Get returns the progress recorded for the deployment and reports whether
	// anything has been recorded at all.
	Get(ctx context.Context, deploymentID string) (SeedImageProgress, bool)

	// Reset drops what has been recorded for the deployment, leaving every other
	// deployment, including the ones reading the very same image, alone.
	Reset(ctx context.Context, deploymentID string)
}
