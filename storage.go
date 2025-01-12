package nebula

import (
	"context"

	"github.com/openbao/openbao/sdk/v2/logical"
)

func saveCertificateEntry(ctx context.Context, req *logical.Request, key string, cert interface{}) error {
	entry, err := logical.StorageEntryJSON(key, cert)
	if err != nil {
		return err
	}
	return req.Storage.Put(ctx, entry)
}
