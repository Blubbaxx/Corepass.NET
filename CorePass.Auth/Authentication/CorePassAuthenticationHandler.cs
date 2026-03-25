using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CorePass.Auth;

/// <summary>
/// ASP.NET Core authentication handler for CorePass sessions.
/// Reads token from x-session-token header, Authorization Bearer header, or HttpOnly cookie.
/// Loads session from the store and populates HttpContext.User.
/// </summary>
public sealed class CorePassAuthenticationHandler : AuthenticationHandler<CorePassAuthenticationSchemeOptions>
{
    public const string SchemeName = "CorePass";

    private readonly ICorePassStore _store;
    private readonly CorePassOptions _corePassOptions;

    public CorePassAuthenticationHandler(
        IOptionsMonitor<CorePassAuthenticationSchemeOptions> options,
        ILoggerFactory loggerFactory,
        UrlEncoder encoder,
        ICorePassStore store,
        IOptions<CorePassOptions> corePassOptions)
        : base(options, loggerFactory, encoder)
    {
        _store = store;
        _corePassOptions = corePassOptions.Value;
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var token = CorePassEndpoints.ExtractToken(Context, _corePassOptions.CookieName);
        if (string.IsNullOrWhiteSpace(token))
        {
            return AuthenticateResult.NoResult();
        }

        var session = await _store.GetSessionByTokenAsync(token);
        if (session is null)
        {
            return AuthenticateResult.NoResult();
        }

        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, session.CoreId),
            new(ClaimTypes.Name, session.Name),
            new("ican", session.Ican),
            new("coreId", session.CoreId),
            new("sessionToken", session.Token)
        };

        var identity = new ClaimsIdentity(claims, SchemeName);
        var principal = new ClaimsPrincipal(identity);
        var ticket = new AuthenticationTicket(principal, SchemeName);

        return AuthenticateResult.Success(ticket);
    }

    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        // For API calls, return 401. For page requests, redirect to /login.
        if (IsApiRequest())
        {
            Response.StatusCode = 401;
            return Task.CompletedTask;
        }

        Response.Redirect("/login");
        return Task.CompletedTask;
    }

    private bool IsApiRequest()
    {
        return Request.Path.StartsWithSegments("/auth")
            || Request.Headers.Accept.Any(h => h?.Contains("application/json") == true)
            || Request.Headers.ContainsKey("x-session-token");
    }
}

/// <summary>
/// Options for the CorePass authentication scheme (empty for now; extends base).
/// </summary>
public sealed class CorePassAuthenticationSchemeOptions : AuthenticationSchemeOptions
{
}
