package pipeline

import (
	"context"
	"sync"
)

type Stage interface {
	Name() string
	Run(ctx context.Context, wg *sync.WaitGroup)
}
