package nebula

import (
	"context"
	"crypto/rand"
	"fmt"
	"strings"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/helper/errutil"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/slackhq/nebula/cert"
	"golang.org/x/crypto/ed25519"
)

func buildPathGenerateCA(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "generate/ca",
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: `Required: name of the certificate authority`,
			},
			"duration": {
				Type:        framework.TypeString,
				Description: `Optional: amount of time the certificate should be valid for. Valid time units are seconds: "s", minutes: "m", hours: "h" (default 8760h0m0s)`,
				Default:     "8760h",
			},
			"groups": {
				Type:        framework.TypeString,
				Description: `Optional: list of groups. This will limit which groups subordinate certs can use.`,
				Default:     "",
			},
			"ips": {
				Type:        framework.TypeString,
				Description: `Optional: list of ip and network in CIDR notation. This will limit which ip addresses and networks subordinate certs can use.`,
				Default:     "",
			},
			"subnets": {
				Type:        framework.TypeString,
				Description: `Optional: list of ip and network in CIDR notation. This will limit which subnet addresses and networks subordinate certs can use.`,
				Default:     "",
			},
			"rotate": {
				Type:        framework.TypeBool,
				Description: `Optional: if true, rotate the current CA to backup and generate a new one. Required if a non-expired CA exists.`,
				Default:     false,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathGenerateCA,
				Summary:  "",
			},
		},
	}
}

func pathConfigCA(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "config/ca",
		Fields: map[string]*framework.FieldSchema{
			"pem_bundle": {
				Type:        framework.TypeString,
				Description: `PEM-format, unencrypted secret key and cert`,
			},
			"rotate": {
				Type:        framework.TypeBool,
				Description: `If true, rotate the CA certificate by moving the current one to backup and creating a new one`,
				Default:     false,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathConfigCAUpdate,
				Summary:  "Configure or rotate the CA certificate",
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathConfigCADelete,
				Summary:  "Delete the CA certificate",
			},
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathConfigCARead,
				Summary:  "Read the current and previous CA certificates",
			},
		},
	}
}

func (b *backend) pathGenerateCA(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	if name == "" {
		return nil, fmt.Errorf("nebula CA Name may not be empty")
	}

	rotate := data.Get("rotate").(bool)

	// Check for existing CA
	currentCACertEntry, err := req.Storage.Get(ctx, "ca")
	if err != nil {
		return nil, errutil.InternalError{Err: fmt.Sprintf("unable to check for existing CA: %v", err)}
	}

	if currentCACertEntry != nil {
		var currentCA cert.NebulaCertificate
		if err := currentCACertEntry.DecodeJSON(&currentCA); err != nil {
			return nil, errutil.InternalError{Err: fmt.Sprintf("unable to decode current CA: %v", err)}
		}

		// Check if current CA is expired
		isExpired := time.Now().After(currentCA.Details.NotAfter)

		if !isExpired && !rotate {
			return nil, fmt.Errorf("a valid CA certificate already exists; use rotate=true to force rotation")
		}

		// Get current CA key
		currentCAKeyEntry, err := req.Storage.Get(ctx, "ca_key")
		if err != nil {
			return nil, errutil.InternalError{Err: fmt.Sprintf("unable to fetch current CA key: %v", err)}
		}
		if currentCAKeyEntry == nil {
			return nil, errutil.InternalError{Err: "no CA key found"}
		}

		// Decode current CA key to store it properly
		var currentKey ed25519.PrivateKey
		if err := currentCAKeyEntry.DecodeJSON(&currentKey); err != nil {
			return nil, errutil.InternalError{Err: fmt.Sprintf("unable to decode current CA key for backup: %v", err)}
		}

		// Convert CA to PEM for storage
		pemCert, err := currentCA.MarshalToPEM()
		if err != nil {
			return nil, errutil.InternalError{Err: fmt.Sprintf("unable to marshal old CA to PEM: %v", err)}
		}

		// Store old CA as a map to match our read format
		oldCAData := map[string]interface{}{
			"name":       currentCA.Details.Name,
			"public_key": string(pemCert),
			"not_before": currentCA.Details.NotBefore.Format("2006-01-02 15:04:05"),
			"not_after":  currentCA.Details.NotAfter.Format("2006-01-02 15:04:05"),
		}

		// Move current CA and key to old CA
		err = saveCertificateEntry(ctx, req, "ca_old", oldCAData)
		if err != nil {
			return nil, errutil.InternalError{Err: fmt.Sprintf("unable to save old CA: %v", err)}
		}

		err = saveCertificateEntry(ctx, req, "ca_key_old", currentKey)
		if err != nil {
			return nil, errutil.InternalError{Err: fmt.Sprintf("unable to save old CA key: %v", err)}
		}

		// Delete current CA entries as they will be replaced
		if err := req.Storage.Delete(ctx, "ca"); err != nil {
			return nil, errutil.InternalError{Err: fmt.Sprintf("error deleting current CA: %v", err)}
		}
		if err := req.Storage.Delete(ctx, "ca_key"); err != nil {
			return nil, errutil.InternalError{Err: fmt.Sprintf("error deleting current CA key: %v", err)}
		}
	}

	groups := data.Get("groups").(string)
	_groups := parseGroups(groups)

	duration := data.Get("duration").(string)
	var _duration time.Duration
	_duration, err = time.ParseDuration(duration)
	if err != nil {
		return nil, fmt.Errorf("invalid time format: %s", err)
	}

	ips := data.Get("ips").(string)
	_ips, err := parseCIDRList(ips)
	if err != nil {
		return nil, fmt.Errorf("invalid ip definition: %s", err)
	}

	subnets := data.Get("subnets").(string)
	_subnets, err := parseCIDRList(subnets)
	if err != nil {
		return nil, fmt.Errorf("invalid subnet definition: %s", err)
	}

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	nc := cert.NebulaCertificate{
		Details: cert.NebulaCertificateDetails{
			Name:      name,
			Groups:    _groups,
			Ips:       _ips,
			Subnets:   _subnets,
			NotBefore: time.Now(),
			NotAfter:  time.Now().Add(_duration),
			PublicKey: publicKey,
			IsCA:      true,
		},
	}

	nc.Sign(privateKey)

	err = saveCertificateEntry(ctx, req, "ca", nc)
	if err != nil {
		return nil, err
	}

	err = saveCertificateEntry(ctx, req, "ca_key", privateKey)
	if err != nil {
		return nil, err
	}

	pemCert, err := nc.MarshalToPEM()
	if err != nil {
		return nil, err
	}

	fingerprint, err := nc.Sha256Sum()
	if err != nil {
		return nil, err
	}

	var formattedIPs []string
	for _, ipNet := range nc.Details.Ips {
		formattedIPs = append(formattedIPs, ipNet.String())
	}

	var formattedSubnets []string
	for _, subnet := range nc.Details.Subnets {
		formattedSubnets = append(formattedSubnets, subnet.String())
	}

	resp := &logical.Response{
		Data: map[string]interface{}{
			"name":        nc.Details.Name,
			"fingerprint": formatFingerprint(fingerprint),
			"groups":      strings.Join(nc.Details.Groups, ", "),
			"ips":         strings.Join(formattedIPs, ", "),
			"subnets":     strings.Join(formattedSubnets, ", "),
			"notBefore":   nc.Details.NotBefore.Format("2006-01-02 15:04:05"),
			"notAfter":    nc.Details.NotAfter.Format("2006-01-02 15:04:05"),
			"cert":        string(pemCert),
		},
	}

	return resp, nil
}

func (b *backend) pathConfigCAUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	rotate := data.Get("rotate").(bool)
	rawPemBundle, hasPemBundle := data.GetOk("pem_bundle")

	// Check if we're rotating
	if rotate {
		// Get current CA and key
		currentCACertEntry, err := req.Storage.Get(ctx, "ca")
		if err != nil {
			return nil, errutil.InternalError{Err: fmt.Sprintf("unable to fetch current CA: %v", err)}
		}
		if currentCACertEntry == nil {
			return nil, errutil.InternalError{Err: "no CA certificate to rotate"}
		}

		currentCAKeyEntry, err := req.Storage.Get(ctx, "ca_key")
		if err != nil {
			return nil, errutil.InternalError{Err: fmt.Sprintf("unable to fetch current CA key: %v", err)}
		}
		if currentCAKeyEntry == nil {
			return nil, errutil.InternalError{Err: "no CA key found"}
		}

		// Decode current CA to store it properly
		var currentCA cert.NebulaCertificate
		if err := currentCACertEntry.DecodeJSON(&currentCA); err != nil {
			return nil, errutil.InternalError{Err: fmt.Sprintf("unable to decode current CA for backup: %v", err)}
		}

		// Decode current CA key to store it properly
		var currentKey ed25519.PrivateKey
		if err := currentCAKeyEntry.DecodeJSON(&currentKey); err != nil {
			return nil, errutil.InternalError{Err: fmt.Sprintf("unable to decode current CA key for backup: %v", err)}
		}

		// Convert CA to PEM for storage
		pemCert, err := currentCA.MarshalToPEM()
		if err != nil {
			return nil, errutil.InternalError{Err: fmt.Sprintf("unable to marshal old CA to PEM: %v", err)}
		}

		// Store old CA as a map to match our read format
		oldCAData := map[string]interface{}{
			"name":       currentCA.Details.Name,
			"public_key": string(pemCert),
			"not_before": currentCA.Details.NotBefore.Format("2006-01-02 15:04:05"),
			"not_after":  currentCA.Details.NotAfter.Format("2006-01-02 15:04:05"),
		}

		// Move current CA and key to old CA
		err = saveCertificateEntry(ctx, req, "ca_old", oldCAData)
		if err != nil {
			return nil, errutil.InternalError{Err: fmt.Sprintf("unable to save old CA: %v", err)}
		}

		err = saveCertificateEntry(ctx, req, "ca_key_old", currentKey)
		if err != nil {
			return nil, errutil.InternalError{Err: fmt.Sprintf("unable to save old CA key: %v", err)}
		}

		// Delete current CA entries as they will be replaced
		if err := req.Storage.Delete(ctx, "ca"); err != nil {
			return nil, errutil.InternalError{Err: fmt.Sprintf("error deleting current CA: %v", err)}
		}
		if err := req.Storage.Delete(ctx, "ca_key"); err != nil {
			return nil, errutil.InternalError{Err: fmt.Sprintf("error deleting current CA key: %v", err)}
		}
	}

	// If we're not rotating or we're rotating with a new PEM bundle
	if hasPemBundle {
		pemBundle := rawPemBundle.(string)

		if len(pemBundle) == 0 {
			return logical.ErrorResponse("'pem_bundle' is empty"), nil
		}

		if len(pemBundle) < 200 {
			return logical.ErrorResponse("provided data for import was too short; perhaps a path was passed to the API rather than the contents of a PEM file"), nil
		}

		var privateKey ed25519.PrivateKey

		privateKey, rest, err := cert.UnmarshalEd25519PrivateKey([]byte(pemBundle))
		if err != nil {
			return nil, errutil.InternalError{Err: fmt.Sprintf("unable to decode Certificate Key: %v", err)}
		}

		nc, _, err := cert.UnmarshalNebulaCertificateFromPEM(rest)
		if err != nil {
			return nil, errutil.InternalError{Err: fmt.Sprintf("unable to decode Certificate: %v", err)}
		}

		if !nc.Details.IsCA {
			return nil, errutil.InternalError{Err: "Certificate is not a Nebula CA"}
		}

		// Save new CA and key
		err = saveCertificateEntry(ctx, req, "ca", nc)
		if err != nil {
			return nil, err
		}

		err = saveCertificateEntry(ctx, req, "ca_key", privateKey)
		if err != nil {
			return nil, err
		}

		pemCert, err := nc.MarshalToPEM()
		if err != nil {
			return nil, err
		}

		resp := &logical.Response{
			Data: map[string]interface{}{
				"name": nc.Details.Name,
				"cert": string(pemCert),
			},
		}

		return resp, nil
	}

	// If we're rotating without a new PEM bundle, return an error
	if rotate && !hasPemBundle {
		return logical.ErrorResponse("rotation requires either a new PEM bundle or using the generate/ca endpoint"), nil
	}

	// If we're not rotating and don't have a PEM bundle, check if CA exists
	currentCACertEntry, err := req.Storage.Get(ctx, "ca")
	if err != nil {
		return nil, errutil.InternalError{Err: fmt.Sprintf("unable to check for existing CA: %v", err)}
	}
	if currentCACertEntry != nil {
		return nil, fmt.Errorf("CA already present")
	}

	return logical.ErrorResponse("'pem_bundle' not provided"), nil

}

func (b *backend) pathConfigCARead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	// Get current CA
	currentCACertEntry, err := req.Storage.Get(ctx, "ca")
	if err != nil {
		return nil, errutil.InternalError{Err: fmt.Sprintf("unable to fetch current nebula ca: %v", err)}
	}
	if currentCACertEntry == nil {
		return nil, errutil.InternalError{Err: "no CA certificate configured"}
	}

	var currentCA cert.NebulaCertificate
	if err := currentCACertEntry.DecodeJSON(&currentCA); err != nil {
		return nil, errutil.InternalError{Err: fmt.Sprintf("unable to decode current Nebula Certificate: %v", err)}
	}

	currentPEMCert, err := currentCA.MarshalToPEM()
	if err != nil {
		return nil, errutil.InternalError{Err: fmt.Sprintf("unable to marshal current CA to PEM: %v", err)}
	}

	// Get old CA if it exists
	oldCACertEntry, err := req.Storage.Get(ctx, "ca_old")
	if err != nil {
		return nil, errutil.InternalError{Err: fmt.Sprintf("unable to fetch old nebula ca: %v", err)}
	}

	resp := &logical.Response{
		Data: map[string]interface{}{
			"name":       currentCA.Details.Name,
			"public_key": string(currentPEMCert),
			"not_before": currentCA.Details.NotBefore.Format("2006-01-02 15:04:05"),
			"not_after":  currentCA.Details.NotAfter.Format("2006-01-02 15:04:05"),
		},
	}

	// Add old CA to response if it exists
	if oldCACertEntry != nil {
		var oldCAData map[string]interface{}
		if err := oldCACertEntry.DecodeJSON(&oldCAData); err != nil {
			return nil, errutil.InternalError{Err: fmt.Sprintf("unable to decode old CA data: %v", err)}
		}
		resp.Data["name_old"] = oldCAData["name"]
		resp.Data["public_key_old"] = oldCAData["public_key"]
		resp.Data["not_before_old"] = oldCAData["not_before"]
		resp.Data["not_after_old"] = oldCAData["not_after"]
	}

	return resp, nil
}

func (b *backend) pathConfigCADelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return nil, nil
}
