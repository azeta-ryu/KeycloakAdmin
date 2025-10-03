# Keycloak Admin HTTP Client for .NET

A pragmatic, DI-friendly wrapper around an **NSwag-generated Keycloak Admin API client**.  
It adds:

- OAuth2 token acquisition (**client credentials** and **password** flows)
- **Bearer** auth injection via `HttpMessageHandler`
- **Structured request/response logging** with safe redaction + truncation
- A **startup connectivity probe** (`/admin/serverinfo`) with human-readable hints
- **Caching** of access tokens with configurable refresh skew
- Zero-reflection `System.Text.Json` **source-generated** DTOs

> Works with a Keycloak service account (recommended) or a user credential (Direct Access Grants).

---

## Contents

- [Quick start](#quick-start)
- [Configuration](#configuration)
- [Usage](#usage)
- [NSwag generation notes](#nswag-generation-notes)
- [Logging](#logging)
- [Startup probe](#startup-probe)
- [Token cache & refresh](#token-cache--refresh)
- [Troubleshooting](#troubleshooting)
- [FAQ](#faq)
- [License](#license)

---

## Quick start

### 1) Generate the OpenAPI client (NSwag)

Make sure you have a generated client that exposes `KeycloakAdmin.OpenApi.IKeycloakOpenApiClient` and a concrete `KeycloakOpenApiClient(HttpClient http)` constructor. See [NSwag generation notes](#nswag-generation-notes).

### 2) Register services

In your ASP.NET Core app (e.g., `.NET 6+`), wire everything up with a single extension:

```csharp
using KeycloakAdmin;
using KeycloakAdmin.OpenApi;

var builder = WebApplication.CreateBuilder(args);

// Option A: bind from configuration (recommended)
builder.Services.AddKeycloakHttpClient(opts =>
{
    builder.Configuration.GetSection("Keycloak").Bind(opts);
});

// Option B: configure inline
// builder.Services.AddKeycloakHttpClient(opts =>
// {
//     opts.Host = "https://keycloak.example.com";
//     opts.Realm = "master";
//     opts.ClientId = "admin-cli";
//     opts.ClientSecret = "super-secret";
//     opts.Flow = KeycloakAuthFlow.ClientCredentials;
// });

var app = builder.Build();

app.MapGet("/server-info", async (IKeycloakOpenApiClient kc) =>
{
    // Example: call any generated admin endpoint; BaseAddress is already set
    // Replace with your generated method names (e.g., AdminServerinfoAsync())
    return Results.Ok(await kc.AdminServerinfoAsync());
});

app.Run();
```

### 3) Configure `appsettings.json` (example)

```json
{
  "Keycloak": {
    "Host": "https://keycloak.example.com",
    "Realm": "master",
    "ClientId": "my-admin-client",
    "ClientSecret": "replace-me",
    "Scope": null,
    "RefreshSkewSeconds": 60,
    "TokenEndpointOverride": null,
    "Flow": 0,                         // 0 = ClientCredentials, 1 = Password
    "Username": null,                  // required for Password flow
    "Password": null,                  // required for Password flow

    "StartupProbeEnabled": true,
    "StartupProbeTimeoutSeconds": 10,
    "FailFastOnStartup": true,

    "LogRequests": true,
    "LogRequestBody": true,
    "LogResponseBody": true,
    "MaxBodyLogBytes": 4096
  }
}
```

---

## Configuration

`KeycloakClientOptions`:

| Option | Type | Default | Notes |
|---|---|---:|---|
| `Host` | string | `""` | Base Keycloak URL, e.g. `https://keycloak.example.com`. Used as `HttpClient.BaseAddress`. |
| `Realm` | string | `"master"` | Realm for token issuance (the **client’s** realm). |
| `ClientId` | string | `""` | OAuth2 client id. |
| `ClientSecret` | string | `""` | Required for **confidential** clients; optional for public clients using password flow. |
| `Scope` | string? | `null` | Optional scopes (space-separated). |
| `RefreshSkewSeconds` | int | `60` | Refresh tokens early by subtracting this many seconds from `expires_in`. |
| `TokenEndpointOverride` | string? | `null` | Override the computed token URL if needed. |
| `Flow` | `KeycloakAuthFlow` | `ClientCredentials` | `ClientCredentials` or `Password` (Direct Access Grants). |
| `Username` | string? | `null` | Required for `Password` flow. |
| `Password` | string? | `null` | Required for `Password` flow. |
| `StartupProbeEnabled` | bool | `true` | Runs a token check + `/admin/serverinfo` call on startup. |
| `StartupProbeTimeoutSeconds` | int | `10` | Timeout for the probe. |
| `FailFastOnStartup` | bool | `true` | Throw on probe failure (stops app) vs log a warning and continue. |
| `LogRequests` | bool | `true` | Toggle all HTTP logging. |
| `LogRequestBody` | bool | `true` | Log request bodies (JSON/text/XML only). Secrets redacted. |
| `LogResponseBody` | bool | `true` | Log response bodies (JSON/text/XML only). Secrets redacted. |
| `MaxBodyLogBytes` | int | `4096` | Truncate large bodies after this many bytes. |

---

## Usage

Once registered, inject the generated interface anywhere:

```csharp
public sealed class MyController : ControllerBase
{
    private readonly IKeycloakOpenApiClient _kc;

    public MyController(IKeycloakOpenApiClient kc) => _kc = kc;

    [HttpGet("realms/{realm}/users")]
    public async Task<IActionResult> GetUsers(string realm)
    {
        // Use your generated method names; samples may differ by NSwag template
        var users = await _kc.AdminRealmsRealmUsersGetAsync(realm);
        return Ok(users);
    }
}
```

### Choosing an auth flow

- **Client Credentials (recommended)**  
  Configure `ClientId`, `ClientSecret`, set `Flow = ClientCredentials`, and grant the **service account** the required `realm-management` roles (e.g., `view-realm`, or `realm-admin` if you truly need full access).

- **Password (Direct Access Grants)**  
  Set `Flow = Password`, and provide `Username` & `Password`.  
  The client must have **Direct Access Grants** enabled. `ClientSecret` is optional for public clients.

---

## NSwag generation notes

This library expects your OpenAPI client to be generated with:

- `InjectHttpClient = true` (constructor accepts `HttpClient`)
- `UseBaseUrl = false` (the DI code sets `HttpClient.BaseAddress` to `Host`)
- `JsonLibrary = SystemTextJson`

Example `nswag.json` (excerpt):

```json
{
  "codeGenerators": {
    "openApiToCSharpClient": {
      "className": "KeycloakOpenApiClient",
      "namespace": "KeycloakAdmin.OpenApi",
      "injectHttpClient": true,
      "useBaseUrl": false,
      "clientBaseClass": null,
      "generateClientInterfaces": true,
      "generateOptionalParameters": true,
      "jsonLibrary": "SystemTextJson"
    }
  }
}
```

> Ensure the generated interface is named `IKeycloakOpenApiClient` (or update the registration accordingly).

---

## Logging

- The **named** client is `keycloak-admin`.  
- Requests/responses are logged at **Information** level:
  - Method + URL + status + elapsed ms
  - Optional bodies (JSON/text/XML only), **redacted** fields:
    - `client_secret`, `clientSecret`, `password`, `access_token`, `refresh_token`
  - Bodies are **truncated** at `MaxBodyLogBytes`.

> For production, consider disabling `LogRequestBody` / `LogResponseBody` or increasing redaction as needed.

---

## Startup probe

On app start (unless disabled):

1. Acquire a token (using configured flow).
2. Call `GET /admin/serverinfo` via the same pipeline (so it’s logged).
3. On failure, a **human-readable hint** is emitted.  
   If `FailFastOnStartup = true`, the app throws and stops; otherwise it logs a warning and continues.

Common handled failures:
- TLS/SSL issues → actionable message about certificate/hostname
- Socket errors → DNS/firewall/network hints
- Timeouts → suggests checking availability & base URL
- 401/403/404 → role/endpoint/host misconfig explanations

---

## Token cache & refresh

- Tokens are cached in `IMemoryCache` under a key that includes:
  `Host`, `Realm`, `ClientId`, `Flow`, `Username`, and `Scope`.
- Cache lifetime = `expires_in - RefreshSkewSeconds` (minimum 1 second).
- Each outgoing request uses the **Bearer token** from the provider; a fresh token is fetched transparently when needed.

---

## Troubleshooting

| Symptom | Likely Cause | What to check |
|---|---|---|
| `401 unauthorized_client` or body mentions *“not enabled to retrieve service account”* | Client credentials flow but service account not enabled | In the client settings, enable **Client authentication** and **Service accounts roles**. Use the correct **Realm** (the client’s realm) and the client’s **Credentials → Client secret**. |
| `401 invalid_client` or *“invalid client credentials”* | Wrong/rotated secret | Copy the latest secret from the client’s **Credentials** tab. |
| `400 invalid_grant` (client credentials) | Wrong grant | Ensure `grant_type=client_credentials` and **Service accounts roles** is enabled. |
| `400 invalid_grant` (password flow) | Username/password or DAG not enabled | Verify credentials, that the user exists and is enabled. Enable **Direct Access Grants** for the client. |
| `404` from token endpoint | Wrong `Host`/`Realm` or custom path | Verify `Host` and `Realm`. Use `TokenEndpointOverride` if your deployment uses a nonstandard path. |
| `403` calling admin endpoints | Authenticated but missing roles | Grant the service account appropriate `realm-management` roles in the **target realm** (e.g., `view-realm`, or `realm-admin` if necessary). |
| TLS/SSL error during probe | Cert/hostname mismatch or untrusted CA | Verify certificate trust chain and hostnames; use a valid CA-signed cert. |
| Socket/DNS failures | Network or URL issues | Check DNS, firewall, container networking, and the `Host` URL. |

---

## FAQ

**Q: Which .NET version is required?**  
A: The code targets modern `System.Text.Json` source generation and `HttpClientFactory`; **.NET 6 or later** is recommended.

**Q: Can I change the logging level or sink?**  
A: Yes—this uses `ILogger<T>`. Configure sinks/levels via your logging provider. Toggle body logging with options.

**Q: What if my Keycloak sits behind a reverse proxy with a different token path?**  
A: Use `TokenEndpointOverride` to point directly to the correct `/protocol/openid-connect/token` URL.

**Q: Can I call endpoints from multiple realms?**  
A: Token issuance realm is controlled by `Realm`. You can still call other realm endpoints if your service account has the appropriate cross-realm permissions and your generated client methods target those routes.

**Q: Is refresh token used?**  
A: The provider relies on `expires_in` and early refresh; it does not perform refresh-token rotation. The access token is reacquired as needed.

---

## License

MIT (or your project’s license). Add a `LICENSE` file alongside this README.

---

### Credits

- Built on `HttpClientFactory`, `Microsoft.Extensions.*` abstractions, and NSwag-generated clients.
- Secrets are redacted in logs; still, be mindful of logging policies in production.
