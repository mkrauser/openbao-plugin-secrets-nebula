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

type backend struct {
	*framework.Backend

	storage logical.Storage
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
		},
	}

	return &b, nil
}

func buildPathCert(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "cert/" + framework.GenericNameRegex("fingerprint"),
		Fields: map[string]*framework.FieldSchema{
			"fingerprint": {
				Type:        framework.TypeString,
				Description: `Required: fingerprint of the certificate`,
				Required:    true,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathReadCert,
				Summary:  "",
			},
		},
	}
}

func (b *backend) pathReadCert(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	fingerprint := data.Get("fingerprint").(string)
	if fingerprint == "" {
		return nil, fmt.Errorf("nebula Certificate Name may not be empty")
	}

	storageEntry, err := req.Storage.Get(ctx, "certs/"+fingerprint)
	if err != nil {
		return nil, err
	}

	var nc cert.NebulaCertificate
	storageEntry.DecodeJSON(&nc)

	pemCert, err := nc.MarshalToPEM()

	var ipNetStrings []string
	for _, ipNet := range nc.Details.Ips {
		ipNetStrings = append(ipNetStrings, ipNet.String())
	}

	resp := &logical.Response{
		Data: map[string]interface{}{
			"notAfter":    nc.Details.NotAfter.Format("02.01.2006 15:04:05"),
			"name":        nc.Details.Name,
			"ip":          strings.Join(ipNetStrings, ", "),
			"cert":        string(pemCert),
			"fingerprint": fingerprint,
		},
	}

	return resp, err
}

func buildPathSign(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "sign/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: `Required: name of the certificate authority`,
				Required:    true,
			},
			"duration": {
				Type:        framework.TypeString,
				Description: `Optional: amount of time the certificate should be valid for. Valid time units are seconds: "s", minutes: "m", hours: "h". Without passing a -duration XXhXXmXXs flag, certificates will be valid up until one second before their signing CA expires.`,
			},
			"groups": {
				Type:        framework.TypeString,
				Description: `Optional: list of groups. This will limit which groups subordinate certs can use.`,
				Default:     "",
			},
			"ip": {
				Type:        framework.TypeString,
				Description: `Required: ipv4 address and network in CIDR notation to assign the cert.`,
				Required:    true,
			},
			"subnets": {
				Type:        framework.TypeString,
				Description: `Optional: list of ip and network in CIDR notation. This will limit which subnet addresses and networks subordinate certs can use.`,
				Default:     "",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathSign,
				Summary:  "",
			},
		},
	}
}

func (b *backend) pathSign(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	caKeyStorageEntry, err := req.Storage.Get(ctx, "config/ca_key")
	if err != nil {
		return nil, errutil.InternalError{Err: fmt.Sprintf("unable to fetch nebula ca: %v", err)}
	}

	var caPrivateKey ed25519.PrivateKey
	if err := caKeyStorageEntry.DecodeJSON(&caPrivateKey); err != nil {
		return nil, errutil.InternalError{Err: fmt.Sprintf("unable to decode Nebula CA Key: %v", err)}
	}

	nebulaCACertEntry, err := req.Storage.Get(ctx, "config/ca_cert")
	if err != nil {
		return nil, errutil.InternalError{Err: fmt.Sprintf("unable to fetch nebula ca: %v", err)}
	}

	var caCert cert.NebulaCertificate
	if err := nebulaCACertEntry.DecodeJSON(&caCert); err != nil {
		return nil, errutil.InternalError{Err: fmt.Sprintf("unable to decode Nebula Certificate: %v", err)}
	}

	name := data.Get("name").(string)
	if name == "" {
		return nil, fmt.Errorf("nebula Certificate Name may not be empty")
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

	duration, durationOk := data.GetOk("duration")

	var _duration time.Duration
	if !durationOk {
		_duration = time.Until(caCert.Details.NotAfter) - time.Second*1
	} else {
		_duration, err = time.ParseDuration(duration.(string))
		if err != nil {
			return nil, fmt.Errorf("Invalid time format: %s", err)
		}
	}

	ip := data.Get("ip").(string)
	var _ip []*net.IPNet
	if ip != "" {
		rs := strings.Trim(ip, " ")
		if rs != "" {
			ip, ipNet, err := net.ParseCIDR(rs)
			if err != nil {
				return nil, fmt.Errorf("invalid ip definition: %s", err)
			}
			ipNet.IP = ip
			_ip = append(_ip, ipNet)
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
		return nil, errutil.InternalError{Err: fmt.Sprintf("Failed to generate keypair: %v", err)}
	}

	issuer, _ := caCert.Sha256Sum()

	newCertificate := cert.NebulaCertificate{
		Details: cert.NebulaCertificateDetails{
			Name:      name,
			Groups:    _groups,
			Ips:       _ip,
			Subnets:   _subnets,
			NotBefore: time.Now(),
			NotAfter:  time.Now().Add(_duration),
			PublicKey: publicKey,
			Issuer:    issuer,
			IsCA:      false,
		},
	}

	err = newCertificate.Sign(caPrivateKey)

	if err != nil {
		return nil, errutil.InternalError{Err: fmt.Sprintf("failed to sign certificate: %v", err)}
	}

	pemCert, _ := newCertificate.MarshalToPEM()
	fingerprint, _ := newCertificate.Sha256Sum()

	entry, err := logical.StorageEntryJSON("certs/"+fingerprint, newCertificate)
	if err != nil {
		return nil, err
	}

	err = req.Storage.Put(ctx, entry)
	if err != nil {
		return nil, err
	}

	resp := &logical.Response{
		Data: map[string]interface{}{
			"notAfter":    time.Now().Add(_duration).Format("02.01.2006 15:04:05"),
			"name":        newCertificate.Details.Name,
			"cert":        string(pemCert),
			"private_key": string(cert.MarshalEd25519PrivateKey(privateKey)),
			"fingerprint": fingerprint,
		},
	}

	return resp, err
}

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
	_duration, err := time.ParseDuration(duration)
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

	entry, err := logical.StorageEntryJSON("config/ca_cert", nc)
	if err != nil {
		return nil, err
	}

	err = req.Storage.Put(ctx, entry)
	if err != nil {
		return nil, err
	}

	entry, err = logical.StorageEntryJSON("config/ca_key", privateKey)
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

func (b *backend) pathConfigCAUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	rawPemBundle, ok := data.GetOk("pem_bundle")

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
	entry, err := logical.StorageEntryJSON("config/ca_key", privateKey)
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

	entry, err = logical.StorageEntryJSON("config/ca_cert", nc)
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
	nebulaCACertEntry, err := req.Storage.Get(ctx, "config/ca_cert")
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

const backendHelp = `
The Nebula backend generates Nebula style Curve25519 certs.
`
