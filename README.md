OpenID Connect (OIDC) Pluggable Authentication Module for Linux

## What is this?

This project is a Pluggable Authentication Module (PAM) for Linux that implements OpenID Connect (OIDC)-based authentication.

## Features

- Configurable username claim
- AMD64 and ARM64 support

## Documentation

/etc/pam.d/pam_oidc_auth

```
auth required pam_oidc_auth.so discovery_url=https://login.microsoftonline.com/{TenantId}/v2.0/.well-known/openid-configuration audience=f6e6e114-1007-49e0-b15d-dd4812968345 username_claim=preferred_username
```