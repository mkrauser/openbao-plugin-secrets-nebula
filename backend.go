package nebula

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

type backend struct {
	*framework.Backend

	storage logical.Storage

	// Tidy operations
	tidyStatus     TidyStatus
	tidyStatusLock sync.RWMutex
	tidyCancelCAS  uint32

	// Auto-tidy operations
	autoTidyCtx    context.Context
	autoTidyCancel context.CancelFunc
	autoTidyLock   sync.Mutex
}

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b, err := Backend()
	if err != nil {
		return nil, err
	}

	if conf == nil {
		return nil, fmt.Errorf("configuration passed into backend is nil")
	}

	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}

	return b, nil
}

func Backend() (*backend, error) {
	var b backend

	b.Backend = &framework.Backend{
		Help:        strings.TrimSpace(backendHelp),
		BackendType: logical.TypeLogical,
		Paths: []*framework.Path{
			buildPathGenerateCA(&b),
			pathConfigCA(&b),
			buildPathSign(&b),
			buildPathCert(&b),
			buildPathListCerts(&b),
			buildPathRevoke(&b),
			buildPathListCertsRevoked(&b),
			buildPathTidy(&b),
			buildPathTidyCancel(&b),
			buildPathTidyStatus(&b),
			buildPathConfigAutoTidy(&b),
		},
		Clean: b.cleanup,
	}

	// Initialize tidy status
	b.tidyStatus = tidyStatusDefault

	return &b, nil
}

func (b *backend) cleanup(ctx context.Context) {
	b.stopAutoTidy()
}

const backendHelp = `
The Nebula backend generates Nebula style Curve25519 certs.
`
