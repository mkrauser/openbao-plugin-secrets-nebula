# openbao-plugin-secrets-nebula[WIP]

Openbao Secrets Engine plugin for creating a Slack Nebula CA and node certificates. This is a work in progress.

# How to use

```
# enable nebula plugin
bao secrets enable -path=nebula -plugin-name=bao-plugin-secrets-nebula plugin

# generate ca
bao write nebula/generate/ca name="ca-name" duration="8760h" ips="10.0.0.0/20"

# or import existing ca
# the file bundle.pem contains the private key followed by the ca-certificate
bao write nebula/config/ca pem_bundle=@bundle.pem

# get the ca from vault
bao read nebula/config/ca

# generate a host certificate
bao write nebula/sign/example.com \
    ip="10.0.0.1/32" \
    duration="100h"

# read a certificate
bao read nebula/cert/<fingerprint>

# list certificates
bao list nebula/certs

# write tidy config
bao write nebula/config/auto-tidy 
    enabled=true \
    interval_duration="24h" \
    tidy_expired_certs=true \
    tidy_revoked_certs=true \
    safety_buffer="168h"  # 1 week safety buffer

# confirm tidy config

bao read nebula/config/auto-tidy

# invoke tidy manually
bao write nebula/tidy \
    enabled=true \
    interval_duration="24h" \
    tidy_expired_certs=true \
    tidy_revoked_certs=true \
    safety_buffer="48h"
```

## 🤝 Contributing

Contributions are welcome!
