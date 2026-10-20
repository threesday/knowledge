# SQL Credentials in Azure Key Vault for ASP.NET Core

How to store and load SQL authentication credentials from Azure Key Vault in ASP.NET Core apps, including on-prem apps and vaults shared across multiple applications.

## Whole connection string vs. credentials only

Security is roughly equal either way: the password is the only real secret. The difference is operational.

| | Whole connection string in KV | Credentials only in KV |
|---|---|---|
| Setup | Simplest: binds directly to `ConnectionStrings:Default`, no composition code | A few lines to compose the string |
| Non-secret config (server, timeouts, MARS) | Hidden in the vault | Visible and diffable in `appsettings.{Environment}.json` |
| Least privilege | Vault holds non-secret data too | Vault holds only secrets |

**Recommendation:** store only the credentials and build the string with `SqlConnectionStringBuilder` (never string concatenation, which breaks on passwords containing `;` or `=`). Storing the whole string is still reasonable for small apps with few environments.

## Keep the username in Key Vault too

The username isn't strictly a secret, but store it alongside the password:

- **They belong together.** Split across sources, one gets updated without the other, causing a login failure found only at deploy time.
- **Easier rotation.** The two-account pattern (`app_svc_a` / `app_svc_b`: reset the inactive account's password, switch the app over, later rotate the other) changes the username on every rotation. With both in the vault, rotation needs no config deploy.
- **Slightly less for an attacker.** A known valid login helps password spraying and recon.

## Authenticating on-prem apps to Key Vault

The real question for on-prem apps is how they authenticate to Key Vault. A client secret in `appsettings.json` just moves the problem.

1. **Azure Arc-enabled servers:** the on-prem machine gets a system-assigned managed identity, so `DefaultAzureCredential` works and access is granted with RBAC. Cleanest option.
2. **Service principal with a certificate:** cert in the machine store, ideally non-exportable with the private key ACL'd to the app identity, used via `ClientCertificateCredential`. Requires managing cert expiry.
3. **Service principal with a client secret:** avoid. Weakest of the three.

## Shared vaults across multiple apps

**Naming is not isolation.** Key Vault access is mostly granted at the vault level: any app with *Key Vault Secrets User* can read every secret in it. Per-secret RBAC exists but gets messy. Microsoft's guidance is one vault per app per environment. If a vault must be shared, the mapping below is organization, not a security boundary.

The default configuration provider also loads **every** secret in the vault into the app's configuration. A custom `KeyVaultSecretManager` fixes both problems for a shared vault: each app declares in configuration which secrets it reads and which config key each one binds to, so existing secret names work as-is.

## Full example: secret-name mapping

**Packages**

```
Azure.Extensions.AspNetCore.Configuration.Secrets
Azure.Identity
Microsoft.EntityFrameworkCore.SqlServer
```

**appsettings.Production.json**

```json
{
  "ConnectionStrings": {
    "Default": "Server=sqlprod01;Database=Orders;Encrypt=True;"
  },
  "KeyVault": {
    "Uri": "https://shared-kv.vault.azure.net/",
    "SecretMappings": {
      "sql-orders-login": "Db:User",
      "sql-orders-pwd": "Db:Password"
    }
  }
}
```

Put the `KeyVault` section in the environment-specific file, not the base `appsettings.json`. Configuration sources merge, so an empty `SecretMappings` in a later file won't clear mappings from the base file. For local development, keep `Db:User` / `Db:Password` in user-secrets.

**MappedKeyVaultSecretManager.cs**

```csharp
using Azure.Extensions.AspNetCore.Configuration.Secrets;
using Azure.Security.KeyVault.Secrets;

public sealed class MappedKeyVaultSecretManager : KeyVaultSecretManager
{
    private readonly Dictionary<string, string> _map;

    // Key Vault secret names are case-insensitive, so the lookup is too
    public MappedKeyVaultSecretManager(IDictionary<string, string> map) =>
        _map = new Dictionary<string, string>(map, StringComparer.OrdinalIgnoreCase);

    // Only pull mapped secrets; everything else in the shared vault is skipped
    public override bool Load(SecretProperties secret) =>
        secret.Enabled == true && _map.ContainsKey(secret.Name);

    // Return the configuration key the secret should bind to
    public override string GetKey(KeyVaultSecret secret) => _map[secret.Name];
}
```

**DbCredentials.cs**

```csharp
using System.ComponentModel.DataAnnotations;

public sealed class DbCredentials
{
    [Required] public string User { get; init; } = "";
    [Required] public string Password { get; init; } = "";
}
```

**Program.cs**

```csharp
using Azure.Extensions.AspNetCore.Configuration.Secrets;
using Azure.Identity;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

var builder = WebApplication.CreateBuilder(args);

// 1. Read the mappings from config already loaded (appsettings, env vars)
var kvSection = builder.Configuration.GetSection("KeyVault");
var mappings = kvSection.GetSection("SecretMappings")
    .GetChildren()
    .ToDictionary(c => c.Key, c => c.Value!);

// 2. Add Key Vault as a config source, filtered to only the mapped secrets
if (mappings.Count > 0)
{
    builder.Configuration.AddAzureKeyVault(
        new Uri(kvSection["Uri"]!),
        // On-prem: picks up an Azure Arc managed identity, or swap in
        // ClientCertificateCredential for a cert-based service principal
        new DefaultAzureCredential(),
        new AzureKeyVaultConfigurationOptions
        {
            Manager = new MappedKeyVaultSecretManager(mappings)
        });
}

// 3. Bind and validate credentials; fails fast at startup if a mapped secret is missing
builder.Services.AddOptions<DbCredentials>()
    .Bind(builder.Configuration.GetSection("Db"))
    .ValidateDataAnnotations()
    .ValidateOnStart();

// 4. Compose the connection string from non-secret config + vault credentials
builder.Services.AddDbContext<AppDbContext>((sp, options) =>
{
    var creds = sp.GetRequiredService<IOptions<DbCredentials>>().Value;

    var csb = new SqlConnectionStringBuilder(
        builder.Configuration.GetConnectionString("Default"))
    {
        UserID = creds.User,
        Password = creds.Password
    };

    options.UseSqlServer(csb.ConnectionString);
});

var app = builder.Build();
app.Run();
```

### Notes

- **Missing secrets fail loudly.** If a mapped secret doesn't exist or can't be read, the manager never produces that key. `ValidateOnStart` stops the app at startup instead of failing on the first database call.
- **Disabled secrets are skipped**, so a secret disabled mid-rotation won't be loaded.
- **Rotation without a restart** needs `ReloadInterval` on `AzureKeyVaultConfigurationOptions` plus `IOptionsMonitor<DbCredentials>` (`.CurrentValue`) so each new `DbContext` reads the latest values. As written, rotated credentials are picked up on restart.
