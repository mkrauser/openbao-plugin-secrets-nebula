package nebula

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/slackhq/nebula/cert"
)

type RevocationDetails struct {
	Fingerprint string    `json:"fingerprint"`
	RevokedAt   time.Time `json:"revokedAt"`
}

func buildPathRevoke(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "revoke",
		Fields: map[string]*framework.FieldSchema{
			"fingerprint": {
				Type:        framework.TypeString,
				Description: `Required: fingerprint of the certificate`,
				Required:    true,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathRevokeCert,
				// This should never be forwarded. See backend.go for more information.
				// If this needs to write, the entire request will be forwarded to the
				// active node of the current performance cluster, but we don't want to
				// forward invalid revoke requests there.
				Responses: map[int][]framework.Response{
					http.StatusOK: {{
						Description: "OK",
						Fields: map[string]*framework.FieldSchema{
							"revocation_time": {
								Type:        framework.TypeInt64,
								Description: `Revocation Time`,
								Required:    false,
							},
							"revocation_time_rfc3339": {
								Type:        framework.TypeTime,
								Description: `Revocation Time`,
								Required:    false,
							},
							"state": {
								Type:        framework.TypeString,
								Description: `Revocation State`,
								Required:    false,
							},
						},
					}},
				},
			},
		},
	}
}

func (b *backend) pathRevokeCert(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	fingerprint := data.Get("fingerprint").(string)
	if fingerprint == "" {
		return nil, fmt.Errorf("please Specify Certificate Fingerprint")
	}

	if len(fingerprint) != 79 {
		return nil, fmt.Errorf("invalid Fingerprint")
	}

	cleanFingerprint := strings.ReplaceAll(fingerprint, ":", "")
	storageEntry, err := req.Storage.Get(ctx, "certs/"+cleanFingerprint)
	if err != nil {
		return nil, fmt.Errorf("Certificate not found")
	}

	var nc cert.NebulaCertificate
	storageEntry.DecodeJSON(&nc)

	if nc.Details.NotAfter.Before(time.Now()) {
		return nil, fmt.Errorf("certificate already expired at " + nc.Details.NotAfter.Format("02.01.2006 15:04:05"))
	}

	revocationDetails := RevocationDetails{Fingerprint: cleanFingerprint, RevokedAt: time.Now()}

	entry, err := logical.StorageEntryJSON("revoked/"+cleanFingerprint, revocationDetails)
	if err != nil {
		return nil, err
	}

	err = req.Storage.Put(ctx, entry)
	if err != nil {
		return nil, err
	}

	pemCert, err := nc.MarshalToPEM()

	var ipNetStrings []string
	for _, ipNet := range nc.Details.Ips {
		ipNetStrings = append(ipNetStrings, ipNet.String())
	}

	resp := &logical.Response{
		Data: map[string]interface{}{
			"notAfter":                nc.Details.NotAfter.Format("02.01.2006 15:04:05"),
			"name":                    nc.Details.Name,
			"ip":                      strings.Join(ipNetStrings, ", "),
			"cert":                    string(pemCert),
			"fingerprint":             fingerprint, // is already formatted
			"revocation_time":         revocationDetails.RevokedAt.Unix(),
			"revocation_time_rfc3339": revocationDetails.RevokedAt.Format(time.RFC3339),
		},
	}

	return resp, err
}
