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

func buildPathListCerts(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "certs/",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: "nebula",
			OperationSuffix: "certs",
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{
				Callback: b.pathCertList,
			},
		},

		HelpSynopsis:    "List all Certificates",
		HelpDescription: "List the fingerprints of all certificates",
	}
}

func (b *backend) pathCertList(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, "certs/")
	if err != nil {
		return nil, err
	}

	for i, str := range entries {
		entries[i] = formatFingerprint(str)
	}

	caStorageEntry, err := req.Storage.Get(ctx, "ca")
	var nc cert.NebulaCertificate
	caStorageEntry.DecodeJSON(&nc)

	fingerprint, err := nc.Sha256Sum()
	entries = append(entries, formatFingerprint(fingerprint))

	return logical.ListResponse(entries), nil
}

func buildPathCert(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "cert/" + framework.MatchAllRegex("fingerprint"),
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
		return nil, fmt.Errorf("Please Specify Certificate Fingerprint")
	}

	if len(fingerprint) != 79 {
		return nil, fmt.Errorf("Invalid Fingerprint")
	}

	cleanFingerprint := strings.ReplaceAll(fingerprint, ":", "")
	storageEntry, err := req.Storage.Get(ctx, "certs/"+cleanFingerprint)
	if err != nil {
		return nil, fmt.Errorf("Invalid Fingerprint" + cleanFingerprint)
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
			"fingerprint": formatFingerprint(fingerprint),
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
	caKeyStorageEntry, err := req.Storage.Get(ctx, "ca_key")
	if err != nil {
		return nil, errutil.InternalError{Err: fmt.Sprintf("unable to fetch nebula ca: %v", err)}
	}

	var caPrivateKey ed25519.PrivateKey
	if err := caKeyStorageEntry.DecodeJSON(&caPrivateKey); err != nil {
		return nil, errutil.InternalError{Err: fmt.Sprintf("unable to decode Nebula CA Key: %v", err)}
	}

	nebulaCACertEntry, err := req.Storage.Get(ctx, "ca")
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
	_groups := parseGroups(groups)

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
			"fingerprint": formatFingerprint(fingerprint),
		},
	}

	return resp, err
}
