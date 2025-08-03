package nebula

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/slackhq/nebula/cert"
)

// TidyConfig holds the configuration for automatic tidying
type TidyConfig struct {
	Enabled          bool          `json:"tidy_cert_store"`
	TidyRevokedCerts bool          `json:"tidy_revoked_certs"`
	TidyExpiredCerts bool          `json:"tidy_expired_certs"`
	SafetyBuffer     time.Duration `json:"safety_buffer"`
	IntervalDuration time.Duration `json:"interval_duration"`
	PauseDuration    time.Duration `json:"pause_duration"`
}

// TidyStatus holds the current status of tidy operations
type TidyStatus struct {
	SafetyBuffer            time.Duration `json:"safety_buffer"`
	TidyExpiredCerts        bool          `json:"tidy_expired_certs"`
	TidyRevokedCerts        bool          `json:"tidy_revoked_certs"`
	State                   string        `json:"state"`
	Error                   string        `json:"error"`
	TimeStarted             time.Time     `json:"time_started,omitempty"`
	TimeFinished            time.Time     `json:"time_finished,omitempty"`
	Message                 string        `json:"message"`
	CertStoreDeletedCount   uint64        `json:"cert_store_deleted_count"`
	RevokedCertDeletedCount uint64        `json:"revoked_cert_deleted_count"`
	MissingIssuerCertCount  uint64        `json:"missing_issuer_cert_count"`
	CurrentCertStoreCount   uint64        `json:"current_cert_store_count,omitempty"`
	CurrentRevokedCertCount uint64        `json:"current_revoked_cert_count,omitempty"`
}

var tidyStatusDefault = TidyStatus{
	State:   "Inactive",
	Message: "Tidying Inactive",
}

func buildPathTidy(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "tidy$",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: "nebula",
			OperationSuffix: "tidy",
		},

		Fields: map[string]*framework.FieldSchema{
			"safety_buffer": {
				Type:        framework.TypeDurationSecond,
				Description: `The amount of extra time that must have passed beyond certificate expiry before it is removed from the backend storage. Defaults to 72 hours.`,
				Default:     int(72 * time.Hour / time.Second), // 72 hours
			},
			"tidy_expired_certs": {
				Type:        framework.TypeBool,
				Description: `Set to true to enable tidying up the certificate store`,
				Default:     false,
			},
			"tidy_revoked_certs": {
				Type:        framework.TypeBool,
				Description: `Set to true to expire all revoked and expired certificates, removing them both from the CRL and from storage.`,
				Default:     false,
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathTidyWrite,
				Summary:  "Tidy up the backend by removing expired certificates",
			},
		},

		HelpSynopsis:    pathTidyHelpSyn,
		HelpDescription: pathTidyHelpDesc,
	}
}

func buildPathTidyCancel(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "tidy-cancel$",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: "nebula",
			OperationSuffix: "tidy-cancel",
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathTidyCancelWrite,
				Summary:  "Cancel the currently running tidy operation",
			},
		},

		HelpSynopsis:    pathTidyCancelHelpSyn,
		HelpDescription: pathTidyCancelHelpDesc,
	}
}

func buildPathTidyStatus(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "tidy-status$",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: "nebula",
			OperationSuffix: "tidy-status",
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathTidyStatusRead,
				Summary:  "Returns the status of the tidy operation",
			},
		},

		HelpSynopsis:    pathTidyStatusHelpSyn,
		HelpDescription: pathTidyStatusHelpDesc,
	}
}

func buildPathConfigAutoTidy(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "config/auto-tidy$",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: "nebula",
			OperationSuffix: "auto-tidy-configuration",
		},

		Fields: map[string]*framework.FieldSchema{
			"enabled": {
				Type:        framework.TypeBool,
				Description: `Set to true to enable automatic tidy operations.`,
				Default:     false,
			},
			"interval_duration": {
				Type:        framework.TypeDurationSecond,
				Description: `Specifies the duration between automatic tidy operation runs. Defaults to 12 hours.`,
				Default:     int(12 * time.Hour / time.Second), // 12 hours
			},
			"tidy_cert_store": {
				Type:        framework.TypeBool,
				Description: `Set to true to enable tidying up the certificate store`,
				Default:     false,
			},
			"tidy_revoked_certs": {
				Type:        framework.TypeBool,
				Description: `Set to true to remove expired revoked certificates from storage.`,
				Default:     false,
			},
			"tidy_expired_certs": {
				Type:        framework.TypeBool,
				Description: `Set to true to remove expired certificates from storage.`,
				Default:     false,
			},
			"safety_buffer": {
				Type:        framework.TypeDurationSecond,
				Description: `The amount of extra time that must have passed beyond certificate expiry before it is removed from the backend storage. Defaults to 72 hours.`,
				Default:     int(72 * time.Hour / time.Second), // 72 hours
			},
			"pause_duration": {
				Type:        framework.TypeDurationSecond,
				Description: `The amount of time to pause between processing certificates. Defaults to 0 seconds.`,
				Default:     0,
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathConfigAutoTidyRead,
				Summary:  "Return the current configuration for automatic tidy operation",
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathConfigAutoTidyWrite,
				Summary:  "Set the configuration for automatic tidy operation",
			},
		},

		HelpSynopsis:    pathConfigAutoTidyHelpSyn,
		HelpDescription: pathConfigAutoTidyHelpDesc,
	}
}

func (b *backend) pathTidyWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	safetyBuffer := data.Get("safety_buffer").(int)
	tidyExpiredCerts := data.Get("tidy_expired_certs").(bool)
	tidyRevokedCerts := data.Get("tidy_revoked_certs").(bool)

	if !tidyExpiredCerts && !tidyRevokedCerts {
		return logical.ErrorResponse("No work to do: specify one or more tidy operations"), nil
	}

	// Get the current status and check if tidy is already running
	b.tidyStatusLock.RLock()
	if b.tidyStatus.State == "Running" {
		b.tidyStatusLock.RUnlock()
		return logical.ErrorResponse("Tidy operation already in progress"), nil
	}
	b.tidyStatusLock.RUnlock()

	// Set up the tidy status
	b.tidyStatusLock.Lock()
	b.tidyStatus = TidyStatus{
		SafetyBuffer:     time.Duration(safetyBuffer) * time.Second,
		TidyExpiredCerts: tidyExpiredCerts,
		TidyRevokedCerts: tidyRevokedCerts,
		State:            "Running",
		TimeStarted:      time.Now(),
		Message:          "Tidying in progress",
	}
	b.tidyStatusLock.Unlock()

	// Run the tidy operation in the background
	go b.doTidyOperation(context.Background(), req, &b.tidyStatus)

	resp := &logical.Response{}
	resp.AddWarning("Tidy operation successfully started. Monitor the /tidy-status endpoint for progress.")

	return resp, nil
}

func (b *backend) pathTidyCancelWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	b.tidyStatusLock.Lock()
	defer b.tidyStatusLock.Unlock()

	if b.tidyStatus.State == "Running" {
		atomic.StoreUint32(&b.tidyCancelCAS, 1)
		b.tidyStatus.State = "Cancelling"
		return nil, nil
	}

	return logical.ErrorResponse("No tidy operation currently running"), nil
}

func (b *backend) pathTidyStatusRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	b.tidyStatusLock.RLock()
	defer b.tidyStatusLock.RUnlock()

	resp := &logical.Response{
		Data: map[string]interface{}{
			"safety_buffer":              b.tidyStatus.SafetyBuffer / time.Second,
			"tidy_expired_certs":         b.tidyStatus.TidyExpiredCerts,
			"tidy_revoked_certs":         b.tidyStatus.TidyRevokedCerts,
			"state":                      b.tidyStatus.State,
			"error":                      b.tidyStatus.Error,
			"time_started":               b.tidyStatus.TimeStarted,
			"time_finished":              b.tidyStatus.TimeFinished,
			"message":                    b.tidyStatus.Message,
			"cert_store_deleted_count":   b.tidyStatus.CertStoreDeletedCount,
			"revoked_cert_deleted_count": b.tidyStatus.RevokedCertDeletedCount,
			"missing_issuer_cert_count":  b.tidyStatus.MissingIssuerCertCount,
			"current_cert_store_count":   b.tidyStatus.CurrentCertStoreCount,
			"current_revoked_cert_count": b.tidyStatus.CurrentRevokedCertCount,
		},
	}

	return resp, nil
}

func (b *backend) pathConfigAutoTidyRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	entry, err := req.Storage.Get(ctx, "config/auto-tidy")
	if err != nil {
		return nil, err
	}

	// Return default configuration if not set
	if entry == nil {
		return &logical.Response{
			Data: map[string]interface{}{
				"enabled":            false,
				"interval_duration":  int(12 * time.Hour / time.Second),
				"tidy_cert_store":    false,
				"tidy_revoked_certs": false,
				"tidy_expired_certs": false,
				"safety_buffer":      int(72 * time.Hour / time.Second),
				"pause_duration":     0,
			},
		}, nil
	}

	var config TidyConfig
	if err := entry.DecodeJSON(&config); err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"enabled":            config.Enabled,
			"interval_duration":  int(config.IntervalDuration / time.Second),
			"tidy_cert_store":    config.TidyRevokedCerts || config.TidyExpiredCerts,
			"tidy_revoked_certs": config.TidyRevokedCerts,
			"tidy_expired_certs": config.TidyExpiredCerts,
			"safety_buffer":      int(config.SafetyBuffer / time.Second),
			"pause_duration":     int(config.PauseDuration / time.Second),
		},
	}, nil
}

func (b *backend) pathConfigAutoTidyWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config := TidyConfig{
		Enabled:          data.Get("enabled").(bool),
		IntervalDuration: time.Duration(data.Get("interval_duration").(int)) * time.Second,
		TidyRevokedCerts: data.Get("tidy_revoked_certs").(bool),
		TidyExpiredCerts: data.Get("tidy_expired_certs").(bool),
		SafetyBuffer:     time.Duration(data.Get("safety_buffer").(int)) * time.Second,
		PauseDuration:    time.Duration(data.Get("pause_duration").(int)) * time.Second,
	}

	entry, err := logical.StorageEntryJSON("config/auto-tidy", config)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	// Start or stop the automatic tidy process
	if config.Enabled {
		b.startAutoTidy(ctx, req, &config)
	} else {
		b.stopAutoTidy()
	}

	return nil, nil
}

func (b *backend) doTidyOperation(ctx context.Context, req *logical.Request, status *TidyStatus) {
	// Update status when done
	defer func() {
		b.tidyStatusLock.Lock()
		defer b.tidyStatusLock.Unlock()

		if atomic.LoadUint32(&b.tidyCancelCAS) == 1 {
			b.tidyStatus.State = "Cancelled"
			b.tidyStatus.Message = "Tidying cancelled"
		} else {
			b.tidyStatus.State = "Finished"
			b.tidyStatus.Message = "Tidying completed"
		}
		b.tidyStatus.TimeFinished = time.Now()
		atomic.StoreUint32(&b.tidyCancelCAS, 0)
	}()

	safetyBuffer := status.SafetyBuffer
	tidyExpiredCerts := status.TidyExpiredCerts
	tidyRevokedCerts := status.TidyRevokedCerts

	// Tidy expired certificates
	if tidyExpiredCerts {
		if err := b.tidyExpiredCertificates(ctx, req, safetyBuffer); err != nil {
			b.tidyStatusLock.Lock()
			b.tidyStatus.Error = err.Error()
			b.tidyStatusLock.Unlock()
			return
		}
	}

	// Tidy revoked certificates
	if tidyRevokedCerts {
		if err := b.tidyRevokedCertificates(ctx, req, safetyBuffer); err != nil {
			b.tidyStatusLock.Lock()
			b.tidyStatus.Error = err.Error()
			b.tidyStatusLock.Unlock()
			return
		}
	}
}

func (b *backend) tidyExpiredCertificates(ctx context.Context, req *logical.Request, safetyBuffer time.Duration) error {
	entries, err := req.Storage.List(ctx, "certs/")
	if err != nil {
		return fmt.Errorf("failed to list certificates: %v", err)
	}

	currentTime := time.Now()
	deletedCount := uint64(0)

	for _, entry := range entries {
		// Check for cancellation
		if atomic.LoadUint32(&b.tidyCancelCAS) == 1 {
			return nil
		}

		// Load certificate
		storageEntry, err := req.Storage.Get(ctx, "certs/"+entry)
		if err != nil {
			continue // Skip on error, don't fail the whole operation
		}
		if storageEntry == nil {
			continue
		}

		var nc cert.NebulaCertificate
		if err := storageEntry.DecodeJSON(&nc); err != nil {
			continue // Skip invalid certificate
		}

		// Check if certificate is expired beyond safety buffer
		expiryTime := nc.Details.NotAfter.Add(safetyBuffer)
		if currentTime.After(expiryTime) {
			// Delete the certificate
			if err := req.Storage.Delete(ctx, "certs/"+entry); err != nil {
				// Log error but continue
				continue
			}
			deletedCount++

			// Update status
			b.tidyStatusLock.Lock()
			b.tidyStatus.CertStoreDeletedCount = deletedCount
			b.tidyStatusLock.Unlock()
		}
	}

	return nil
}

func (b *backend) tidyRevokedCertificates(ctx context.Context, req *logical.Request, safetyBuffer time.Duration) error {
	entries, err := req.Storage.List(ctx, "revoked/")
	if err != nil {
		return fmt.Errorf("failed to list revoked certificates: %v", err)
	}

	currentTime := time.Now()
	deletedCount := uint64(0)

	for _, entry := range entries {
		// Check for cancellation
		if atomic.LoadUint32(&b.tidyCancelCAS) == 1 {
			return nil
		}

		// Load revocation details
		revokedEntry, err := req.Storage.Get(ctx, "revoked/"+entry)
		if err != nil {
			continue
		}
		if revokedEntry == nil {
			continue
		}

		var revocationDetails RevocationDetails
		if err := revokedEntry.DecodeJSON(&revocationDetails); err != nil {
			continue
		}

		// Try to load the original certificate to check expiry
		certEntry, err := req.Storage.Get(ctx, "certs/"+entry)
		if err != nil || certEntry == nil {
			// Certificate doesn't exist, safe to remove revocation record
			if err := req.Storage.Delete(ctx, "revoked/"+entry); err == nil {
				deletedCount++
			}
			continue
		}

		var nc cert.NebulaCertificate
		if err := certEntry.DecodeJSON(&nc); err != nil {
			continue
		}

		// Check if certificate is expired beyond safety buffer
		expiryTime := nc.Details.NotAfter.Add(safetyBuffer)
		if currentTime.After(expiryTime) {
			// Delete the revocation record
			if err := req.Storage.Delete(ctx, "revoked/"+entry); err != nil {
				continue
			}
			deletedCount++

			// Update status
			b.tidyStatusLock.Lock()
			b.tidyStatus.RevokedCertDeletedCount = deletedCount
			b.tidyStatusLock.Unlock()
		}
	}

	return nil
}

func (b *backend) startAutoTidy(ctx context.Context, req *logical.Request, config *TidyConfig) {
	b.stopAutoTidy()

	b.autoTidyLock.Lock()
	defer b.autoTidyLock.Unlock()

	if b.autoTidyCtx != nil && b.autoTidyCtx.Err() == nil {
		return // Already running
	}

	b.autoTidyCtx, b.autoTidyCancel = context.WithCancel(ctx)

	go func() {
		ticker := time.NewTicker(config.IntervalDuration)
		defer ticker.Stop()

		for {
			select {
			case <-b.autoTidyCtx.Done():
				return
			case <-ticker.C:
				b.runAutoTidy(req, config)
			}
		}
	}()
}

func (b *backend) stopAutoTidy() {
	b.autoTidyLock.Lock()
	defer b.autoTidyLock.Unlock()

	if b.autoTidyCancel != nil {
		b.autoTidyCancel()
		b.autoTidyCancel = nil
	}
}

func (b *backend) runAutoTidy(req *logical.Request, config *TidyConfig) {
	// Check if manual tidy is already running
	b.tidyStatusLock.RLock()
	if b.tidyStatus.State == "Running" {
		b.tidyStatusLock.RUnlock()
		return
	}
	b.tidyStatusLock.RUnlock()

	// Set up status for auto-tidy
	b.tidyStatusLock.Lock()
	b.tidyStatus = TidyStatus{
		SafetyBuffer:     config.SafetyBuffer,
		TidyExpiredCerts: config.TidyExpiredCerts,
		TidyRevokedCerts: config.TidyRevokedCerts,
		State:            "Running",
		TimeStarted:      time.Now(),
		Message:          "Auto-tidying in progress",
	}
	b.tidyStatusLock.Unlock()

	// Run tidy operation
	b.doTidyOperation(context.Background(), req, &b.tidyStatus)
}

const pathTidyHelpSyn = `
Tidy up the backend by removing expired certificates, revoked certificates, and cleaning up the certificate store.
`

const pathTidyHelpDesc = `
This endpoint allows cleaning up the backend storage and/or the certificate store by removing certificates
that have expired and passed the safety buffer period. For revoked certificates, they will be removed
from both the backend storage and the certificate store after they have expired and passed the safety buffer.

The 'safety_buffer' parameter is useful to keep certificates that, due to clock skew, might still be
considered valid on other hosts. The default safety buffer is 72 hours.

Certificates are only deleted from backend storage if they have been expired longer than the safety_buffer
duration. If any certificates are cleaned up, the certificate store will be updated.

A manual run shares the same underlying machinery as automatic tidy operations, so while a manual tidy
is running, the automatic tidy will not be executed in parallel (and vice versa).
`

const pathTidyCancelHelpSyn = `
Cancel the currently running tidy operation.
`

const pathTidyCancelHelpDesc = `
This endpoint allows cancelling the currently running tidy operation. Note that this only cancels
the currently running tidy operation, not any queued/future automatic tidy operations.
`

const pathTidyStatusHelpSyn = `
Returns the status of the tidy operation.
`

const pathTidyStatusHelpDesc = `
This endpoint allows checking the status of the tidy operation and progress. This can be used with the
manual tidy operation and/or the automatic tidy.
`

const pathConfigAutoTidyHelpSyn = `
Set or read the configuration for automatic tidy operations.
`

const pathConfigAutoTidyHelpDesc = `
This endpoint allows configuring automatic tidy operations. The automatic tidy
operation will run in the background on the primary instance in the interval
specified, and will clean up certificates expired past the safety buffer.

Each automatic tidy operation will run according to the configuration at the
time of the run; updating this configuration will not affect any operations
currently in progress.

Note that manual tidy operations share the same underlying locking as the
automatic tidy, so while an automatic tidy is running, starting a manual
tidy will fail.
`
