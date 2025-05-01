OpenID Connect (OIDC) Pluggable Authentication Module for Linux

## What is this?

This project is a Pluggable Authentication Module (PAM) for Linux that implements OpenID Connect (OIDC)-based authentication.

## Features

- Configurable username claim
- AMD64 and ARM64 support

## Installation
Download the appropriate (amd/arm) binary from Releases and copy it to `/usr/lib/security`

Create a file named: `/etc/pam.d/oidc_auth`

```
auth required pam_oidc_auth.so discovery_url=https://login.microsoftonline.com/{TenantId}/v2.0/.well-known/openid-configuration audience=f6e6e114-1007-49e0-b15d-dd4812968345 username_claim=preferred_username
```


## Testing
1. Download pamtester

2. Run `pamtester -v oidc_auth name@company.com authenticate`

3. When prompted enter JWT Token

Results should look like
```
pamtester -v oidc_auth name@company.com authenticate
pamtester: invoking pam_start(oidc_auth, name@company.com, ...)
pamtester: performing operation - authenticate
Password:
pamtester: successfully authenticated
```