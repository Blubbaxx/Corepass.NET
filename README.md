# CorePass.Auth

`CorePass.Auth` is a .NET library for integrating CorePass authentication into ASP.NET Core and Blazor applications.

At this point, the package provides a complete implementation of the CorePass authentication flow and will be further improved and expanded over time with KYC features and more.

---

## 1. Install the package

```shell
dotnet add package CorePass.Auth
```

Or use a project reference (same solution):

```shell
dotnet add reference ../CorePass.Auth/CorePass.Auth.csproj
```

---

## 2. Configure `appsettings.json`

Add the following section:

```json
{
  "CorePass": {
    "CoreId": "<YOUR_APP_CORE_ID>",
    "GatewayUrl": "https://your-domain.tld",
    "ChallengeTtlSeconds": 300,
    "SessionTtlSeconds": 86400,
    "MaxStoreEntries": 50000,
    "CleanupIntervalSeconds": 60,
    "LoginType": "callback",
    "VerifySignature": false,
    "UseDistributedCache": false,
    "CookieName": ".CorePass.Session",
    "AuthBasePath": "/auth",
    "AllowedIcans": [],
    "IcanNames": {}
  }
}
```

### Configuration keys

| Key                             | Type       | Default               | Description |
|---------------------------------|------------|-----------------------|-------------|
| `CoreId`                        | `string`   | `""`                  | Your **application** Core ID in the CorePass network (not the user ID). |
| `GatewayUrl`                    | `string`   | `""`                  | Public HTTPS URL of your app. For local development, use a tunnel (for example Dev Tunnels or ngrok). |
| `ChallengeTtlSeconds`           | `int`      | `300`                 | Login challenge lifetime in seconds. |
| `SessionTtlSeconds`             | `int`      | `86400`               | Authenticated session lifetime in seconds (default: 24h). |
| `MaxStoreEntries`               | `int`      | `50000`               | Maximum entries in the in-memory store (DoS mitigation). |
| `CleanupIntervalSeconds`        | `int`      | `60`                  | Cleanup interval for expired entries. |
| `LoginType`                     | `string`   | `"callback"`          | URI login type: `callback`, `app-link`, etc. |
| `VerifySignature`               | `bool`     | `false`               | Enable Ed448 signature verification for callbacks. |
| `UseDistributedCache`           | `bool`     | `false`               | `true` = use Redis/`IDistributedCache` instead of in-memory storage. |
| `CookieName`                    | `string`   | `".CorePass.Session"` | Name of the HttpOnly session cookie. |
| `AuthBasePath`                  | `string`   | `"/auth"`             | Base path for API endpoints (fixed to `/auth` for compatibility). |
| `AllowedIcans`                  | `string[]` | `[]`                  | Whitelist of allowed ICANs. Empty = allow all. |
| `IcanNames`                     | `object`   | `{}`                  | ICAN → display name map, for example `{"CB001": "Alice"}`. |
| `PasskeyTimestampWindowSeconds` | `int`      | `600`                 | Time window for passkey signature validation (10 minutes). |
| `PasskeyFutureSkewSeconds`      | `int`      | `30`                  | Allowed future skew for passkey timestamps. |

---

## 3. Register services in `Program.cs`

```csharp
using CorePass.Auth;

var builder = WebApplication.CreateBuilder(args);

// Step 1: Register CorePass services
builder.Services.AddCorePass(builder.Configuration);

// For Blazor: enable cascading auth state
builder.Services.AddCascadingAuthenticationState();

// ... other services ...

var app = builder.Build();

// Step 2: Configure middleware
app.UseAuthentication();
app.UseAuthorization();

// Step 3: Map CorePass API endpoints
app.MapCorePass();

app.Run();
```

### What `AddCorePass()` registers automatically

- `ICorePassStore` (in-memory or distributed cache, depending on config)
- `CorePassUriBuilder`
- ASP.NET Core authentication handler (scheme: `"CorePass"`)
- authorization services

### What `MapCorePass()` maps automatically

- all API endpoints under `/auth/*`
- cookie endpoint `/auth/set-cookie`

---

## 4. API endpoints (available automatically)

| Method | Path                    | Description |
|--------|-------------------------|-------------|
| POST   | `/auth/challenge`       | Create a new login challenge (QR code + URIs). |
| GET    | `/auth/challenge/{id}`  | Poll challenge status (`pending` / `authenticated` / `expired`). |
| POST   | `/auth/callback`        | Callback from CorePass client after QR scan/approval. |
| GET    | `/auth/app-link`        | App-link callback (query parameters instead of body). |
| GET    | `/auth/session`         | Get current session status. |
| POST   | `/auth/logout`          | End session and clear cookie. |
| GET    | `/auth/mobile-redirect` | Mobile redirect to CorePass app. |
| POST   | `/auth/passkey/data`    | Verify passkey data (Ed448). |
| GET    | `/auth/set-cookie`      | Set session cookie (for Blazor). |

---

## 5. Login flow

```
1. Browser  → POST /auth/challenge       → receives challengeId + QR code
2. Browser displays QR and polls GET /auth/challenge/{id}
3. User scans QR with CorePass app
4. CorePass app → POST /auth/callback    → server validates and creates session
5. Next poll returns status: "authenticated" + token
6. Browser → GET /auth/set-cookie?token=... → HttpOnly cookie is set
7. Redirect user to protected area
```

---

## 6. Protect Blazor pages

```razor
@page "/dashboard"
@using Microsoft.AspNetCore.Authorization
@attribute [Authorize]

<AuthorizeView>
    <Authorized>
        <h1>Welcome, @context.User.Identity?.Name</h1>
        <p>ICAN: @context.User.FindFirst("ican")?.Value</p>
    </Authorized>
</AuthorizeView>
```

---

## 7. Token extraction priority

The package resolves session tokens in this order:

1. `x-session-token` header
2. `Authorization: Bearer <token>` header
3. HttpOnly cookie (name from `CookieName`)

---

## 8. Redis mode (optional)

For multi-node deployments, in `appsettings.json`:

```json
{
  "CorePass": {
    "UseDistributedCache": true
  },
  "ConnectionStrings": {
    "Redis": "redis-host:6379,password=<REDACTED>,ssl=true"
  }
}
```

In `Program.cs` **before** `AddCorePass()`:

```csharp
builder.Services.AddStackExchangeRedisCache(options =>
{
    options.Configuration = builder.Configuration.GetConnectionString("Redis");
    options.InstanceName = "CorePass:";
});

builder.Services.AddCorePass(builder.Configuration);
```

---

## 9. Implement a custom store (optional)

You can provide your own `ICorePassStore` implementation:

```csharp
public class MyCustomStore : ICorePassStore
{
    // Implement all interface members...
}

// Registration (after AddCorePass, overrides default store):
builder.Services.AddSingleton<ICorePassStore, MyCustomStore>();
```

---

## 10. ICAN whitelist

To restrict access to specific users:

```json
{
  "CorePass": {
    "AllowedIcans": ["CB0000000001", "CB0000000002"],
    "IcanNames": {
      "CB0000000001": "Alice",
      "CB0000000002": "Bob"
    }
  }
}
```

Empty list = all ICANs are allowed.

---

## 11. Ed448 signature verification (optional)

When `VerifySignature: true` is enabled:

- Signature must be a hex string (228 hex chars = 114 bytes).
- Public key is taken from long-form ICAN BBAN (57 bytes) or from `X-Public-Key` header (hex/base64) for short-form ICANs.
- Verification uses canonical JSON of `{"coreID": "...", "session": "..."}`.

---

## 12. Dependencies

| Package                                           | Purpose |
|---------------------------------------------------|---------|
| `BouncyCastle.Cryptography`                       | Ed448 signature verification |
| `QRCoder`                                         | PNG QR code generation |
| `Microsoft.Extensions.Caching.StackExchangeRedis` | Redis-backed distributed cache (optional) |

---

## License

MIT