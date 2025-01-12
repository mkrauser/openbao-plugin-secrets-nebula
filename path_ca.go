package nebula

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
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
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathConfigCAUpdate,
				Summary:  "",
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathConfigCADelete,
				Summary:  "",
			},
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathConfigCARead,
				Summary:  "",
			},
		},
	}
}

func (b *backend) pathGenerateCA(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	if name == "" {
		return nil, fmt.Errorf("nebula CA Name may not be empty")
	}

	nebulaCACertEntry, err := req.Storage.Get(ctx, "ca")
	if nebulaCACertEntry != nil && err == nil {
		return nil, fmt.Errorf("CA already present")
	}

	groups := data.Get("groups").(string)
	var _groups []string
	if groups != "" {
		for _, rg := range strings.Split(groups, ",") {
			g := strings.TrimSpace(rg)
			if g != "" {
				_groups = append(_groups, g)
			}
		}
	}

	duration := data.Get("duration").(string)
	var _duration time.Duration
	_duration, err = time.ParseDuration(duration)
	if err != nil {
		return nil, fmt.Errorf("invalid time format: %s", err)
	}

	ips := data.Get("ips").(string)
	var _ips []*net.IPNet
	if ips != "" {
		for _, rs := range strings.Split(ips, ",") {
			rs := strings.Trim(rs, " ")
			if rs != "" {
				ip, ipNet, err := net.ParseCIDR(rs)
				if err != nil {
					return nil, fmt.Errorf("invalid ip definition: %s", err)
				}
				ipNet.IP = ip
				_ips = append(_ips, ipNet)
			}
		}
	}

	subnets := data.Get("subnets").(string)
	var _subnets []*net.IPNet
	if subnets != "" {
		for _, rs := range strings.Split(subnets, ",") {
			rs := strings.Trim(rs, " ")
			if rs != "" {
				_, s, err := net.ParseCIDR(rs)
				if err != nil {
					return nil, fmt.Errorf("invalid subnet definition: %s", err)
				}
				_subnets = append(_subnets, s)
			}
		}
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

	entry, err := logical.StorageEntryJSON("ca", nc)
	if err != nil {
		return nil, err
	}

	err = req.Storage.Put(ctx, entry)
	if err != nil {
		return nil, err
	}

	entry, err = logical.StorageEntryJSON("ca_key", privateKey)
	if err != nil {
		return nil, err
	}

	err = req.Storage.Put(ctx, entry)
	if err != nil {
		return nil, err
	}

	pemCert, err := nc.MarshalToPEM()

	if err != nil {
		return nil, err
	}

	fingerprint, err := nc.Sha256Sum()

	var formattedIPs []string
	for _, ipNet := range nc.Details.Ips {
		formattedIPs = append(formattedIPs, ipNet.String()) // Add the CIDR string representation to the new slice
	}

	var formattedSubnets []string
	for _, subnet := range nc.Details.Subnets {
		formattedSubnets = append(formattedSubnets, subnet.String()) // Add the CIDR string representation to the new slice
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

	return resp, err
}

func (b *backend) pathConfigCAUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	rawPemBundle, ok := data.GetOk("pem_bundle")

	nebulaCACertEntry, err := req.Storage.Get(ctx, "ca")
	if nebulaCACertEntry != nil && err == nil {
		return nil, fmt.Errorf("CA already present")
	}

	if !ok {
		return logical.ErrorResponse("'pem_bundle' not provided"), nil
	}

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

	// save private key
	entry, err := logical.StorageEntryJSON("ca_key", privateKey)
	if err != nil {
		return nil, err
	}

	err = req.Storage.Put(ctx, entry)
	if err != nil {
		return nil, err
	}

	nc, _, err := cert.UnmarshalNebulaCertificateFromPEM(rest)

	if err != nil {
		return nil, errutil.InternalError{Err: fmt.Sprintf("unable to decode Certificate: %v", err)}
	}

	if !nc.Details.IsCA {
		return nil, errutil.InternalError{Err: "Certificate is not a Nebula CA"}
	}

	entry, err = logical.StorageEntryJSON("ca", nc)
	if err != nil {
		return nil, err
	}

	err = req.Storage.Put(ctx, entry)
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

	return resp, err

}

func (b *backend) pathConfigCARead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	nebulaCACertEntry, err := req.Storage.Get(ctx, "ca")
	if err != nil {
		return nil, errutil.InternalError{Err: fmt.Sprintf("unable to fetch nebula ca: %v", err)}
	}

	var nc cert.NebulaCertificate
	if err := nebulaCACertEntry.DecodeJSON(&nc); err != nil {
		return nil, errutil.InternalError{Err: fmt.Sprintf("unable to decode Nebula Certificate: %v", err)}
	}

	certDetails := nc.Details

	pemCert, err := nc.MarshalToPEM()

	resp := &logical.Response{
		Data: map[string]interface{}{
			"name":       certDetails.Name,
			"public_key": string(pemCert),
		},
	}

	return resp, nil
}

func (b *backend) pathConfigCADelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return nil, nil
}
