using Microsoft.Extensions.Options;

namespace CorePass.Auth;

/// <summary>
/// Builds CorePass login URIs matching the reference protocol.
/// </summary>
public sealed class CorePassUriBuilder
{
    private readonly CorePassOptions _options;

    public CorePassUriBuilder(IOptions<CorePassOptions> options)
    {
        _options = options.Value;
    }

    /// <summary>
    /// Build the corepass: login URI.
    /// Format: corepass:login/{coreId}?sess={session}&amp;conn={gateway}&amp;type={loginType}
    /// </summary>
    public string BuildLoginUri(string sessionToken)
    {
        var gateway = _options.GatewayUrl.TrimEnd('/') + _options.AuthBasePath + "/callback";
        return $"corepass:login/{Uri.EscapeDataString(_options.CoreId)}?sess={Uri.EscapeDataString(sessionToken)}&conn={Uri.EscapeDataString(gateway)}&type={Uri.EscapeDataString(_options.LoginType)}";
    }

    /// <summary>
    /// Build the mobile redirect URI (for /auth/mobile-redirect).
    /// </summary>
    public string BuildMobileRedirectUri(string challengeId)
    {
        return $"{_options.GatewayUrl.TrimEnd('/')}{_options.AuthBasePath}/mobile-redirect?challengeId={Uri.EscapeDataString(challengeId)}";
    }

    /// <summary>
    /// Build the app-link URI (HTTPS gateway callback with query params).
    /// Format: https://gateway?signature=...&amp;session=...&amp;coreID=...
    /// </summary>
    public string BuildAppLinkUri(string sessionToken)
    {
        var gateway = _options.GatewayUrl.TrimEnd('/') + _options.AuthBasePath + "/app-link";
        return $"{gateway}?session={Uri.EscapeDataString(sessionToken)}&coreID={Uri.EscapeDataString(_options.CoreId)}";
    }
}
