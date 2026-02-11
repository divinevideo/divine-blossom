# OAuth Admin Login Setup

Manual infrastructure steps required before deploying the OAuth admin login feature.

## 1. Google OAuth Client ID

- Go to [Google Cloud Console > Credentials](https://console.cloud.google.com/apis/credentials)
- Create an **OAuth 2.0 Client ID** (type: Web application)
- Authorized JavaScript origin: `https://blossom.divine.video`
- Note the Client ID for step 4

## 2. GitHub OAuth App

- Go to [GitHub > Settings > Developer settings > OAuth Apps](https://github.com/settings/developers)
- Create a new OAuth App
- Authorization callback URL: `https://blossom.divine.video/admin/auth/github/callback`
- Note the Client ID and Client Secret for step 3

## 3. Fastly Secret Store (`blossom_secrets`)

Add these secrets:

| Secret | Value |
|--------|-------|
| `github_client_id` | GitHub OAuth App Client ID |
| `github_client_secret` | GitHub OAuth App Client Secret |

```bash
fastly secret-store-entry create --store-id=<STORE_ID> --name=github_client_id --stdin
fastly secret-store-entry create --store-id=<STORE_ID> --name=github_client_secret --stdin
```

## 4. Fastly Config Store (`blossom_config`)

Add these entries:

| Key | Value | Description |
|-----|-------|-------------|
| `google_client_id` | `<from step 1>` | Google OAuth Client ID |
| `google_allowed_domain` | `divine.video` | Restrict Google login to this domain |
| `github_allowed_org` | `<org name>` | Restrict GitHub login to this org's members |

```bash
fastly config-store-entry update --store-id=<STORE_ID> --key=google_client_id --value=<CLIENT_ID>
fastly config-store-entry update --store-id=<STORE_ID> --key=google_allowed_domain --value=divine.video
fastly config-store-entry update --store-id=<STORE_ID> --key=github_allowed_org --value=<ORG_NAME>
```

## 5. Fastly Backends

Add three new backends in the [Fastly control panel](https://manage.fastly.com/) or via CLI:

| Backend name | Host | Port | TLS |
|-------------|------|------|-----|
| `google_oauth` | `oauth2.googleapis.com` | 443 | Yes |
| `github_oauth` | `github.com` | 443 | Yes |
| `github_api` | `api.github.com` | 443 | Yes |

```bash
# These must be created via the Fastly UI or API for production backends
# The fastly.toml local_server entries only work for `fastly compute serve`
```

## 6. Deploy

```bash
fastly compute publish --comment "feat: add OAuth admin login" && fastly purge --all --service-id pOvEEWykEbpnylqst1KTrR
```
