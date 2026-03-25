namespace CorePass.Auth;

/// <summary>
/// Configuration options for CorePass authentication.
/// Bind from appsettings "CorePass" section.
/// </summary>
public sealed class CorePassOptions
{
    public const string SectionName = "CorePass";

    /// <summary>
    /// The Core ID that identifies this application in the CorePass network.
    /// </summary>
    public string CoreId { get; set; } = string.Empty;

    /// <summary>
    /// Gateway URL that CorePass clients will call back to (your public base URL).
    /// Must be HTTPS in production.
    /// Example: "https://example.com"
    /// </summary>
    public string GatewayUrl { get; set; } = string.Empty;

    /// <summary>
    /// Challenge TTL in seconds. Default 300 (5 minutes).
    /// </summary>
    public int ChallengeTtlSeconds { get; set; } = 300;

    /// <summary>
    /// Session TTL in seconds. Default 86400 (24 hours).
    /// </summary>
    public int SessionTtlSeconds { get; set; } = 86400;

    /// <summary>
    /// Maximum number of entries in the in-memory store (DoS mitigation).
    /// </summary>
    public int MaxStoreEntries { get; set; } = 50_000;

    /// <summary>
    /// Cleanup interval in seconds for the in-memory store. Default 60.
    /// </summary>
    public int CleanupIntervalSeconds { get; set; } = 60;

    /// <summary>
    /// Allowed ICANs (whitelist). Empty means allow all.
    /// Values are normalized (trimmed + uppercased) at startup.
    /// </summary>
    public List<string> AllowedIcans { get; set; } = [];

    /// <summary>
    /// Map of ICAN to display name. Keys are normalized.
    /// </summary>
    public Dictionary<string, string> IcanNames { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Whether to verify Ed448 signatures on callbacks.
    /// </summary>
    public bool VerifySignature { get; set; }

    /// <summary>
    /// Use Redis/IDistributedCache instead of in-memory store.
    /// </summary>
    public bool UseDistributedCache { get; set; }

    /// <summary>
    /// Cookie name for session token transport (for Blazor circuits).
    /// </summary>
    public string CookieName { get; set; } = ".CorePass.Session";

    /// <summary>
    /// Auth endpoint base path. Hardcoded to /auth to match reference URIs.
    /// </summary>
    public string AuthBasePath { get; set; } = "/auth";

    /// <summary>
    /// Timestamp tolerance window for passkey/data verification in seconds. Default 600 (10 min).
    /// </summary>
    public int PasskeyTimestampWindowSeconds { get; set; } = 600;

    /// <summary>
    /// Passkey timestamp future skew allowance in seconds. Default 30.
    /// </summary>
    public int PasskeyFutureSkewSeconds { get; set; } = 30;

    /// <summary>
    /// Login type for the CorePass URI: "callback", "app-link", etc. Default "callback".
    /// </summary>
    public string LoginType { get; set; } = "callback";
}
