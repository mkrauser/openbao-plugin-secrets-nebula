# OpenBao Nebula Secrets Plugin

A secrets engine plugin for [OpenBao](https://github.com/openbao/openbao) that manages [Slack Nebula](https://github.com/slackhq/nebula) certificates. This plugin enables you to:

- Generate and manage Nebula Certificate Authority (CA)
- Issue and manage node certificates
- Automatically rotate CA certificates
- Clean up expired and revoked certificates

> [!NOTE]  
> for Vault Users: I developed and tested this against openbao. 
> I did some basic testing with vault, which looked promising.
> If you test this with vault, please let me know if you run into any issues.

## Features

- **CA Management**:
  - Generate new CA certificates
  - Import existing CA certificates
  - Rotate CA certificates with backup preservation
  - View current and previous CA certificates

- **Node Certificate Management**:
  - Issue node certificates
  - List all issued certificates
  - View individual certificate details
  - Revoke certificates

- **Automatic Maintenance**:
  - Configure automatic cleanup of expired certificates
  - Set safety buffer periods for certificate cleanup
  - Manual and scheduled cleanup operations

## Installation

1. Download the latest plugin binary from the releases page
2. Register the plugin with OpenBao:
```shell
# Move the plugin to OpenBao's plugin directory
mv bao-plugin-secrets-nebula /etc/openbao/plugins/

# Calculate the SHA256 sum of the plugin
SHA256=$(sha256sum /etc/openbao/plugins/bao-plugin-secrets-nebula | cut -d' ' -f1)

# Register the plugin
bao write sys/plugins/catalog/secret/bao-plugin-secrets-nebula \
    sha256=$SHA256 \
    command="bao-plugin-secrets-nebula"
```

## Usage

### Enable the Plugin

```shell
bao secrets enable -path=nebula -plugin-name=bao-plugin-secrets-nebula plugin
```

### CA Certificate Management

1. Generate a new CA:
```shell
# Generate a new CA with a 1-year validity period
bao write nebula/generate/ca \
    name="my-nebula-ca" \
    duration="8760h" \
    ips="10.0.0.0/20" \
    groups="servers,clients"
```

2. Import an existing CA:
```shell
# Import CA from a PEM bundle (private key + certificate)
bao write nebula/config/ca pem_bundle=@bundle.pem
```

3. Read CA information:
```shell
bao read nebula/config/ca
```

4. Rotate CA certificate:
```shell
# Rotate with a new generated CA
bao write nebula/generate/ca name="new-ca" rotate=true

# Or rotate with an imported CA
bao write nebula/config/ca pem_bundle=@new_bundle.pem rotate=true
```

### Node Certificate Management

1. Issue a node certificate:
```shell
bao write nebula/sign/example.com \
    ip="10.0.0.1/32" \
    duration="720h" \
    groups="servers"
```

2. List all certificates:
```shell
bao list nebula/certs
```

3. View certificate details:
```shell
bao read nebula/cert/<fingerprint>
```

### Certificate Cleanup

1. Configure automatic cleanup:
```shell
bao write nebula/config/auto-tidy \
    enabled=true \
    interval_duration="24h" \
    tidy_expired_certs=true \
    tidy_revoked_certs=true \
    safety_buffer="168h"  # 1 week safety buffer
```

2. View cleanup configuration:
```shell
bao read nebula/config/auto-tidy
```

3. Run manual cleanup:
```shell
bao write nebula/tidy \
    tidy_expired_certs=true \
    tidy_revoked_certs=true \
    safety_buffer="48h"
```

## Development

### Prerequisites

- Go 1.19 or higher
- OpenBao development environment

### Building

```shell
# Clone the repository
git clone https://github.com/yourusername/openbao-plugin-secrets-nebula
cd openbao-plugin-secrets-nebula

# Build the plugin
make build
```

### Testing

```shell
# Run tests
make test
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

## License

This project is licensed under the [MIT License](LICENSE).