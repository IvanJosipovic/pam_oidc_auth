# OpenID Connect (OIDC) Pluggable Authentication Module for Linux

## What is this?

This project is a Pluggable Authentication Module (PAM) for Linux that implements OpenID Connect (OIDC)-based authentication.

## Features
- Automatic discovery via the `/.well‑known/openid‑configuration` endpoint
- JWT Validation
  - Signature and key verification
  - Issuer, audience, expiry, and not‑before (`nbf`) checks
- Configurable username claim (defaults to `preferred_username`)
- Pre‑built binaries for amd64 and arm64
## Installation
1. Download the appropriate (amd/arm) binary from [Releases](https://github.com/IvanJosipovic/pam_oidc_auth/releases) and copy it to
    - x64  `/lib/x86_64-linux-gnu/security/pam_oidc_auth.so`
    - axm64 `/lib/aarch64-linux-gnu/security/pam_oidc_auth.so`
1. Create a file named: `/etc/pam.d/oidc_auth`
1. Enter `auth required pam_oidc_auth.so {Param}=Value`
  - Parameters:
    - Name: `discovery_url`
      - Description: URL to the OpenID Connect discovery document. Eg `https://login.microsoftonline.com/{TenantId}/v2.0/.well-known/openid-configuration`
      - Required: true
    - Name: `audience`
      - Description: The audience claim in the JWT token. This is usually the client ID of the application.
      - Required: true
    - Name: `username_claim`
      - Description: The claim in the JWT token that will be used as the username. This is usually `preferred_username` or `email`.
      - Required: false, default: `preferred_username`

```
auth required pam_oidc_auth.so discovery_url=https://login.microsoftonline.com/{TenantId}/v2.0/.well-known/openid-configuration audience=f6e6e114-1007-49e0-b15d-dd4812968345 username_claim=preferred_username
```

## Testing
1. Download [pamtester](https://pamtester.sourceforge.net)

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

## Postgres
1. Complete the Installation steps above
1. Edit `/etc/pam.d/oidc_auth` and append on a new line `account  sufficient  pam_permit.so`
1. Update pg_hba.conf
    - `host all all all pam pamservice=oidc_auth`
1. Create User
    ```
    CREATE ROLE "someuser@company.com" LOGIN PASSWORD NULL;
    GRANT CONNECT ON DATABASE postgres TO "someuser@company.com";
    ```
[Example](/tests/pam_oidc_auth_tests/Dockerfile.postgres#L63-L69)
