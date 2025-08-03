package nebula

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/slackhq/nebula/cert"
	"golang.org/x/crypto/ed25519"
)

func TestTidyOperation(t *testing.T) {
	b, reqStorage := createBackendWithStorage(t)

	// Create some test certificates - one expired and one current
	expiredCert := createTestCertificate(t, time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour))
	currentCert := createTestCertificate(t, time.Now().Add(-1*time.Hour), time.Now().Add(24*time.Hour))

	// Store the certificates
	expiredEntry, _ := logical.StorageEntryJSON("certs/expired123", expiredCert)
	reqStorage.Put(context.Background(), expiredEntry)

	currentEntry, _ := logical.StorageEntryJSON("certs/current123", currentCert)
	reqStorage.Put(context.Background(), currentEntry)

	// Test manual tidy operation
	tidyReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "tidy",
		Storage:   reqStorage,
		Data: map[string]interface{}{
			"tidy_expired_certs": true,
			"safety_buffer":      1800, // 30 minutes
		},
	}

	resp, err := b.HandleRequest(context.Background(), tidyReq)
	if err != nil {
		t.Fatalf("Tidy operation failed: %v", err)
	}

	if resp.IsError() {
		t.Fatalf("Tidy operation returned error: %v", resp.Error())
	}

	// Wait a moment for the background operation to complete
	time.Sleep(100 * time.Millisecond)

	// Check tidy status
	statusReq := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "tidy-status",
		Storage:   reqStorage,
	}

	statusResp, err := b.HandleRequest(context.Background(), statusReq)
	if err != nil {
		t.Fatalf("Failed to read tidy status: %v", err)
	}

	if statusResp.Data["state"].(string) == "Running" {
		// Wait for completion
		for i := 0; i < 50; i++ {
			time.Sleep(100 * time.Millisecond)
			statusResp, _ = b.HandleRequest(context.Background(), statusReq)
			if statusResp.Data["state"].(string) != "Running" {
				break
			}
		}
	}

	// Verify the expired certificate was deleted
	expiredCheck, err := reqStorage.Get(context.Background(), "certs/expired123")
	if err != nil {
		t.Fatalf("Error checking expired certificate: %v", err)
	}
	if expiredCheck != nil {
		t.Error("Expected expired certificate to be deleted")
	}

	// Verify the current certificate was not deleted
	currentCheck, err := reqStorage.Get(context.Background(), "certs/current123")
	if err != nil {
		t.Fatalf("Error checking current certificate: %v", err)
	}
	if currentCheck == nil {
		t.Error("Expected current certificate to still exist")
	}
}

func TestTidyRevokedCertificates(t *testing.T) {
	b, reqStorage := createBackendWithStorage(t)

	// Create an expired certificate and revoke it
	expiredCert := createTestCertificate(t, time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour))
	fingerprint := "expiredrevoked123"

	// Store the certificate
	certEntry, _ := logical.StorageEntryJSON("certs/"+fingerprint, expiredCert)
	reqStorage.Put(context.Background(), certEntry)

	// Create a revocation record
	revocationDetails := RevocationDetails{
		Fingerprint: fingerprint,
		RevokedAt:   time.Now().Add(-30 * time.Hour),
	}
	revokeEntry, _ := logical.StorageEntryJSON("revoked/"+fingerprint, revocationDetails)
	reqStorage.Put(context.Background(), revokeEntry)

	// Test tidy operation for revoked certificates
	tidyReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "tidy",
		Storage:   reqStorage,
		Data: map[string]interface{}{
			"tidy_revoked_certs": true,
			"safety_buffer":      1800, // 30 minutes
		},
	}

	resp, err := b.HandleRequest(context.Background(), tidyReq)
	if err != nil {
		t.Fatalf("Tidy operation failed: %v", err)
	}

	if resp.IsError() {
		t.Fatalf("Tidy operation returned error: %v", resp.Error())
	}

	// Wait for completion
	time.Sleep(100 * time.Millisecond)

	statusReq := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "tidy-status",
		Storage:   reqStorage,
	}

	for i := 0; i < 50; i++ {
		statusResp, _ := b.HandleRequest(context.Background(), statusReq)
		if statusResp.Data["state"].(string) != "Running" {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Verify the revocation record was deleted
	revokeCheck, err := reqStorage.Get(context.Background(), "revoked/"+fingerprint)
	if err != nil {
		t.Fatalf("Error checking revoked certificate: %v", err)
	}
	if revokeCheck != nil {
		t.Error("Expected revoked certificate record to be deleted")
	}
}

func TestAutoTidyConfiguration(t *testing.T) {
	b, reqStorage := createBackendWithStorage(t)

	// Test setting auto-tidy configuration
	configReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/auto-tidy",
		Storage:   reqStorage,
		Data: map[string]interface{}{
			"enabled":            true,
			"interval_duration":  3600, // 1 hour
			"tidy_expired_certs": true,
			"tidy_revoked_certs": true,
			"safety_buffer":      7200, // 2 hours
			"pause_duration":     0,
		},
	}

	resp, err := b.HandleRequest(context.Background(), configReq)
	if err != nil {
		t.Fatalf("Failed to set auto-tidy config: %v", err)
	}

	if resp != nil && resp.IsError() {
		t.Fatalf("Auto-tidy config returned error: %v", resp.Error())
	}

	// Test reading auto-tidy configuration
	readReq := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config/auto-tidy",
		Storage:   reqStorage,
	}

	readResp, err := b.HandleRequest(context.Background(), readReq)
	if err != nil {
		t.Fatalf("Failed to read auto-tidy config: %v", err)
	}

	if readResp.Data["enabled"].(bool) != true {
		t.Error("Expected auto-tidy to be enabled")
	}

	if readResp.Data["interval_duration"].(int) != 3600 {
		t.Error("Expected interval_duration to be 3600")
	}

	if readResp.Data["tidy_expired_certs"].(bool) != true {
		t.Error("Expected tidy_expired_certs to be true")
	}

	if readResp.Data["safety_buffer"].(int) != 7200 {
		t.Error("Expected safety_buffer to be 7200")
	}
}

func TestTidyCancel(t *testing.T) {
	b, reqStorage := createBackendWithStorage(t)

	// Try to cancel when no tidy is running
	cancelReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "tidy-cancel",
		Storage:   reqStorage,
	}

	resp, err := b.HandleRequest(context.Background(), cancelReq)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if !resp.IsError() {
		t.Error("Expected error when no tidy operation is running")
	}
}

func TestTidyStatus(t *testing.T) {
	b, reqStorage := createBackendWithStorage(t)

	// Test reading tidy status when no operation has run
	statusReq := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "tidy-status",
		Storage:   reqStorage,
	}

	resp, err := b.HandleRequest(context.Background(), statusReq)
	if err != nil {
		t.Fatalf("Failed to read tidy status: %v", err)
	}

	if resp.Data["state"].(string) != "Inactive" {
		t.Errorf("Expected state to be 'Inactive', got %s", resp.Data["state"].(string))
	}

	if resp.Data["message"].(string) != "Tidying Inactive" {
		t.Errorf("Expected message to be 'Tidying Inactive', got %s", resp.Data["message"].(string))
	}
}

func TestTidyValidation(t *testing.T) {
	b, reqStorage := createBackendWithStorage(t)

	// Test tidy operation with no operations specified
	tidyReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "tidy",
		Storage:   reqStorage,
		Data: map[string]interface{}{
			"tidy_expired_certs": false,
			"tidy_revoked_certs": false,
		},
	}

	resp, err := b.HandleRequest(context.Background(), tidyReq)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if !resp.IsError() {
		t.Error("Expected error when no tidy operations are specified")
	}

	expectedError := "No work to do: specify one or more tidy operations"
	if !strings.Contains(resp.Error().Error(), expectedError) {
		t.Errorf("Expected error message to contain '%s', got '%s'", expectedError, resp.Error().Error())
	}
}

// Helper function to create a test certificate
func createTestCertificate(t *testing.T, notBefore, notAfter time.Time) cert.NebulaCertificate {
	publicKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	return cert.NebulaCertificate{
		Details: cert.NebulaCertificateDetails{
			Name:      "test-cert",
			Groups:    []string{"test"},
			NotBefore: notBefore,
			NotAfter:  notAfter,
			PublicKey: publicKey,
			IsCA:      false,
		},
	}
}

// Helper function to create backend with storage for testing
func createBackendWithStorage(t *testing.T) (*backend, logical.Storage) {
	b, err := Backend()
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}

	storage := &logical.InmemStorage{}
	return b, storage
}

// Test CA bundle for use in tests
const testCABundle = `-----BEGIN NEBULA ED25519 PRIVATE KEY-----
Kh7aNaRlChtSySxzeTIQHsJyWnHktMkr4q2YOCzh1eE=
-----END NEBULA ED25519 PRIVATE KEY-----
-----BEGIN NEBULA CERTIFICATE-----
CkUKFXJvb3QtY2EubmouZHJld2Z1cy5vcmcSJTg5YmQ5OWM4LWE5ZGEtNDc2YS04
ZDFkLTAwZGNmNDMwNDYzZRABGgMIAhADKiAAFKLK89AJJ0FE7J0EQY9kq5XQ0c8X
iY5W8e2kOjF1WN0=
-----END NEBULA CERTIFICATE-----`
