package receivers

import (
	"context"
	"sync"
)

type Receiver interface {
	Name() string
	Start(ctx context.Context, wg *sync.WaitGroup) error
}
