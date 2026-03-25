using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CorePass.Auth;

internal sealed class CorePassEndpointLog;

/// <summary>
/// Minimal API endpoint definitions for CorePass authentication.
/// All endpoints are mounted at /auth (matching the Node reference package).
/// </summary>
public static class CorePassEndpoints
{
    public static RouteGroupBuilder MapCorePassEndpoints(this WebApplication app)
    {
        var group = app.MapGroup("/auth")
            .WithTags("CorePass Auth");

        group.MapPost("/challenge", CreateChallenge);
        group.MapPost("/callback", HandleCallback);
        group.MapGet("/app-link", HandleAppLink);
        group.MapGet("/challenge/{id}", GetChallengeStatus);
        group.MapGet("/session", GetSession);
        group.MapPost("/logout", Logout);
        group.MapGet("/mobile-redirect", MobileRedirect);
        group.MapPost("/passkey/data", VerifyPasskeyData);

        return group;
    }

    /// <summary>
    /// POST /auth/challenge — Create a new login challenge.
    /// </summary>
    private static async Task<IResult> CreateChallenge(
        ICorePassStore store,
        CorePassUriBuilder uriBuilder,
        IOptions<CorePassOptions> options,
        ILogger<CorePassEndpointLog> logger,
        HttpContext httpContext)
    {
        var opts = options.Value;
        var challengeId = CryptoHelper.GenerateChallengeId();
        var sessionToken = CryptoHelper.GenerateSessionToken();
        var now = DateTimeOffset.UtcNow;
        var ttl = TimeSpan.FromSeconds(opts.ChallengeTtlSeconds);

        var challenge = new ChallengeEntry
        {
            ChallengeId = challengeId,
            SessionToken = sessionToken,
            CreatedAt = now,
            ExpiresAt = now.Add(ttl)
        };

        try
        {
            // Store challenge by ID (for polling)
            await store.SaveChallengeAsync(challenge);

            // Store reverse mapping: session token → challenge (for callback lookup)
            var reverseEntry = new ChallengeEntry
            {
                ChallengeId = $"session:{sessionToken}",
                SessionToken = sessionToken,
                Reason = challengeId,
                CreatedAt = now,
                ExpiresAt = now.Add(ttl)
            };
            await store.SaveChallengeAsync(reverseEntry);
        }
        catch (InvalidOperationException)
        {
            logger.LogWarning("Challenge creation rejected: store capacity exceeded. IP={IP}",
                httpContext.Connection.RemoteIpAddress);
            return Results.Json(new ErrorResponse { Error = "Service temporarily unavailable" },
                statusCode: 503);
        }

        var loginUri = uriBuilder.BuildLoginUri(sessionToken);
        var mobileUri = uriBuilder.BuildMobileRedirectUri(challengeId);
        var appLinkUri = uriBuilder.BuildAppLinkUri(sessionToken);

        string? qrDataUrl = null;
        try
        {
            qrDataUrl = QrCodeHelper.GenerateDataUrl(loginUri);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "QR code generation failed for challenge {ChallengeId}", challengeId);
        }

        logger.LogInformation(
            "Challenge created: {ChallengeId}, IP={IP}, UA={UserAgent}",
            challengeId,
            httpContext.Connection.RemoteIpAddress,
            httpContext.Request.Headers.UserAgent.ToString());

        return Results.Ok(new ChallengeResponse
        {
            ChallengeId = challengeId,
            LoginUri = loginUri,
            MobileUri = mobileUri,
            AppLinkUri = appLinkUri,
            ExpiresIn = opts.ChallengeTtlSeconds,
            QrDataUrl = qrDataUrl
        });
    }

    /// <summary>
    /// POST /auth/callback — CorePass client callback after user scans QR / approves.
    /// </summary>
    private static async Task<IResult> HandleCallback(
        [FromBody] CallbackRequest body,
        ICorePassStore store,
        IOptions<CorePassOptions> options,
        ILogger<CorePassEndpointLog> logger,
        HttpContext httpContext)
    {
        var opts = options.Value;
        var sessionId = body.ResolvedSession;
        var coreId = body.ResolvedCoreId;

        if (string.IsNullOrWhiteSpace(sessionId) || string.IsNullOrWhiteSpace(coreId))
        {
            return Results.Json(new ErrorResponse { Error = "Missing session or coreId" },
                statusCode: 400);
        }

        // Normalize ICAN
        var normalizedIcan = IcanUtility.Normalize(coreId);

        // Whitelist check
        var allowedIcans = opts.AllowedIcans
            .Select(IcanUtility.Normalize)
            .ToList();

        if (!IcanUtility.IsAllowed(normalizedIcan, allowedIcans))
        {
            logger.LogWarning(
                "Callback rejected: ICAN {Ican} not in whitelist. IP={IP}, UA={UserAgent}",
                normalizedIcan,
                httpContext.Connection.RemoteIpAddress,
                httpContext.Request.Headers.UserAgent.ToString());
            return Results.Json(new ErrorResponse { Error = "Access denied" }, statusCode: 403);
        }

        // Ed448 signature verification (when enabled)
        if (opts.VerifySignature)
        {
            if (!VerifyCallbackSignature(body, normalizedIcan, sessionId, coreId, httpContext, logger))
            {
                return Results.Json(new ErrorResponse { Error = "Signature verification failed" }, statusCode: 403);
            }
        }

        // Reverse lookup: find challenge by session token
        var reverseEntry = await store.GetChallengeAsync($"session:{sessionId}");
        if (reverseEntry is null)
        {
            return Results.Json(new ErrorResponse { Error = "Unknown session" }, statusCode: 404);
        }

        var realChallengeId = reverseEntry.Reason;
        if (string.IsNullOrWhiteSpace(realChallengeId))
        {
            return Results.Json(new ErrorResponse { Error = "Invalid session mapping" }, statusCode: 500);
        }

        var challenge = await store.GetChallengeAsync(realChallengeId);
        if (challenge is null || challenge.Status == ChallengeStatus.Expired)
        {
            return Results.Json(new ErrorResponse { Error = "Challenge expired" }, statusCode: 410);
        }

        if (challenge.Status != ChallengeStatus.Pending)
        {
            return Results.Json(new ErrorResponse { Error = "Challenge already resolved" }, statusCode: 409);
        }

        // Resolve display name
        var normalizedNames = opts.IcanNames
            .ToDictionary(
                kvp => IcanUtility.Normalize(kvp.Key),
                kvp => kvp.Value,
                StringComparer.OrdinalIgnoreCase);
        var displayName = IcanUtility.ResolveName(normalizedIcan, normalizedNames);

        // Create auth session
        var authToken = CryptoHelper.GenerateSessionToken();
        var now = DateTimeOffset.UtcNow;
        var session = new SessionEntry
        {
            Token = authToken,
            CoreId = normalizedIcan,
            Ican = normalizedIcan,
            Name = displayName,
            CreatedAt = now,
            ExpiresAt = now.AddSeconds(opts.SessionTtlSeconds)
        };

        await store.SaveSessionAsync(session);

        // Update challenge status
        challenge.Status = ChallengeStatus.Authenticated;
        challenge.AuthToken = authToken;
        challenge.CoreId = normalizedIcan;
        challenge.Ican = normalizedIcan;
        challenge.Name = displayName;
        await store.UpdateChallengeAsync(challenge);

        // Clean up reverse mapping
        await store.DeleteChallengeAsync($"session:{sessionId}");

        logger.LogInformation(
            "Callback success: ICAN={Ican}, ChallengeId={ChallengeId}, IP={IP}, UA={UserAgent}",
            normalizedIcan,
            challenge.ChallengeId,
            httpContext.Connection.RemoteIpAddress,
            httpContext.Request.Headers.UserAgent.ToString());

        return Results.Ok(new { status = "ok" });
    }

    /// <summary>
    /// GET /auth/app-link — Handle app-link callback (redirect with query params).
    /// </summary>
    private static async Task<IResult> HandleAppLink(
        [FromQuery] string? session,
        [FromQuery] string? coreID,
        [FromQuery] string? signature,
        ICorePassStore store,
        IOptions<CorePassOptions> options,
        ILogger<CorePassEndpointLog> logger,
        HttpContext httpContext)
    {
        var body = new CallbackRequest
        {
            Session = session,
            CoreID = coreID,
            Signature = signature
        };

        return await HandleCallback(body, store, options, logger, httpContext);
    }

    /// <summary>
    /// GET /auth/challenge/{id} — Poll challenge status.
    /// </summary>
    private static async Task<IResult> GetChallengeStatus(
        string id,
        ICorePassStore store)
    {
        var challenge = await store.GetChallengeAsync(id);
        if (challenge is null)
        {
            return Results.Json(new ChallengeStatusResponse { Status = "expired" }, statusCode: 404);
        }

        return challenge.Status switch
        {
            ChallengeStatus.Pending => Results.Ok(new ChallengeStatusResponse { Status = "pending" }),
            ChallengeStatus.Authenticated => Results.Ok(new ChallengeStatusResponse
            {
                Status = "authenticated",
                Token = challenge.AuthToken,
                Ican = challenge.Ican,
                Name = challenge.Name
            }),
            ChallengeStatus.Rejected => Results.Ok(new ChallengeStatusResponse
            {
                Status = "rejected",
                Reason = challenge.Reason
            }),
            ChallengeStatus.Expired => Results.Json(
                new ChallengeStatusResponse { Status = "expired" }, statusCode: 410),
            _ => Results.Json(
                new ChallengeStatusResponse { Status = "expired" }, statusCode: 410)
        };
    }

    /// <summary>
    /// GET /auth/session — Get current session info from token.
    /// </summary>
    private static async Task<IResult> GetSession(
        ICorePassStore store,
        IOptions<CorePassOptions> options,
        HttpContext httpContext)
    {
        var token = ExtractToken(httpContext, options.Value.CookieName);
        if (token is null)
        {
            return Results.Ok(new SessionResponse { Authenticated = false });
        }

        var session = await store.GetSessionByTokenAsync(token);
        if (session is null)
        {
            return Results.Ok(new SessionResponse { Authenticated = false });
        }

        return Results.Ok(new SessionResponse
        {
            Authenticated = true,
            CoreId = session.CoreId,
            Ican = session.Ican,
            Name = session.Name
        });
    }

    /// <summary>
    /// POST /auth/logout — Invalidate session and clear cookie.
    /// </summary>
    private static async Task<IResult> Logout(
        ICorePassStore store,
        IOptions<CorePassOptions> options,
        ILogger<CorePassEndpointLog> logger,
        HttpContext httpContext)
    {
        var cookieName = options.Value.CookieName;
        var token = ExtractToken(httpContext, cookieName);
        if (token is not null)
        {
            await store.DeleteSessionByTokenAsync(token);
            logger.LogInformation(
                "Logout: IP={IP}, UA={UserAgent}",
                httpContext.Connection.RemoteIpAddress,
                httpContext.Request.Headers.UserAgent.ToString());
        }

        httpContext.Response.Cookies.Delete(cookieName, new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Strict,
            Path = "/"
        });

        return Results.Ok(new { status = "ok" });
    }

    /// <summary>
    /// GET /auth/mobile-redirect?challengeId=... — Returns HTML that opens corepass: URI
    /// via anchor click() to avoid mobile URI re-encoding.
    /// </summary>
    private static async Task<IResult> MobileRedirect(
        [FromQuery] string? challengeId,
        ICorePassStore store,
        CorePassUriBuilder uriBuilder)
    {
        if (string.IsNullOrWhiteSpace(challengeId))
        {
            return Results.BadRequest(new ErrorResponse { Error = "Missing challengeId" });
        }

        var challenge = await store.GetChallengeAsync(challengeId);
        if (challenge is null || challenge.Status == ChallengeStatus.Expired)
        {
            return Results.NotFound(new ErrorResponse { Error = "Challenge not found or expired" });
        }

        var loginUri = uriBuilder.BuildLoginUri(challenge.SessionToken);
        var html = $"""
            <!DOCTYPE html>
            <html>
            <head><meta charset="utf-8"><title>Redirecting to CorePass...</title></head>
            <body>
                <p>Redirecting to CorePass app...</p>
                <a id="cp" href="{System.Web.HttpUtility.HtmlAttributeEncode(loginUri)}">Open CorePass</a>
                <script>document.getElementById('cp').click();</script>
            </body>
            </html>
            """;

        return Results.Content(html, "text/html");
    }

    /// <summary>
    /// POST /auth/passkey/data — Verify Ed448-signed passkey data.
    /// </summary>
    private static async Task<IResult> VerifyPasskeyData(
        [FromBody] PasskeyDataRequest body,
        ICorePassStore store,
        IOptions<CorePassOptions> options,
        ILogger<CorePassEndpointLog> logger,
        HttpContext httpContext)
    {
        var opts = options.Value;

        if (string.IsNullOrWhiteSpace(body.CoreId) || string.IsNullOrWhiteSpace(body.CredentialId))
        {
            return Results.Json(new ErrorResponse { Error = "Missing coreId or credentialId" }, statusCode: 400);
        }

        // Signature from header
        var signatureHex = httpContext.Request.Headers["X-Signature"].FirstOrDefault();
        if (string.IsNullOrWhiteSpace(signatureHex))
        {
            return Results.Json(new ErrorResponse { Error = "Missing X-Signature header" }, statusCode: 400);
        }

        var sigBytes = Ed448Verifier.HexToBytes(signatureHex);
        if (sigBytes is null || sigBytes.Length != Ed448Verifier.SignatureLengthBytes)
        {
            return Results.Json(new ErrorResponse { Error = "Invalid signature format" }, statusCode: 400);
        }

        // Timestamp validation (microseconds → DateTimeOffset)
        var timestampDto = DateTimeOffset.FromUnixTimeMilliseconds(body.Timestamp / 1000);
        var now = DateTimeOffset.UtcNow;

        if (timestampDto > now.AddSeconds(opts.PasskeyFutureSkewSeconds))
        {
            return Results.Json(new ErrorResponse { Error = "Timestamp too far in the future" }, statusCode: 400);
        }
        if (timestampDto < now.AddSeconds(-opts.PasskeyTimestampWindowSeconds))
        {
            return Results.Json(new ErrorResponse { Error = "Timestamp expired" }, statusCode: 400);
        }

        // Replay protection
        var sigHash = Convert.ToHexStringLower(SHA256.HashData(sigBytes));
        if (await store.HasSignatureHashAsync(sigHash))
        {
            return Results.Json(new ErrorResponse { Error = "Replay detected" }, statusCode: 409);
        }

        // Resolve public key
        var normalizedIcan = IcanUtility.Normalize(body.CoreId);
        byte[]? publicKey = ResolvePublicKey(normalizedIcan, httpContext);
        if (publicKey is null)
        {
            return Results.Json(new ErrorResponse { Error = "Public key not available" }, statusCode: 400);
        }

        // Build verification message
        var bodyJson = JsonSerializer.Serialize(body);
        var canonicalBodyStr = Encoding.UTF8.GetString(CanonicalJson.ToCanonicalBytes(bodyJson));
        var path = opts.AuthBasePath + "/passkey/data";
        var message = Ed448Verifier.BuildPasskeyMessage(path, canonicalBodyStr);

        if (!Ed448Verifier.Verify(publicKey, sigBytes, message))
        {
            logger.LogWarning(
                "Passkey signature verification failed. CoreId={CoreId}, IP={IP}",
                normalizedIcan, httpContext.Connection.RemoteIpAddress);
            return Results.Json(new ErrorResponse { Error = "Signature verification failed" }, statusCode: 403);
        }

        // Store signature hash for replay protection
        var replayTtl = TimeSpan.FromSeconds(opts.PasskeyTimestampWindowSeconds + opts.PasskeyFutureSkewSeconds);
        await store.SaveSignatureHashAsync(sigHash, replayTtl);

        logger.LogInformation(
            "Passkey data verified: CoreId={CoreId}, CredentialId={CredentialId}, IP={IP}",
            normalizedIcan, body.CredentialId, httpContext.Connection.RemoteIpAddress);

        return Results.Ok(new PasskeyDataResponse
        {
            Valid = true,
            CoreId = normalizedIcan,
            CredentialId = body.CredentialId,
            Timestamp = body.Timestamp
        });
    }

    #region Helpers

    /// <summary>
    /// Extract session token from request: x-session-token → Authorization Bearer → cookie.
    /// </summary>
    public static string? ExtractToken(HttpContext httpContext, string cookieName)
    {
        // 1. x-session-token header
        var headerToken = httpContext.Request.Headers["x-session-token"].FirstOrDefault();
        if (!string.IsNullOrWhiteSpace(headerToken))
            return headerToken;

        // 2. Authorization: Bearer <token>
        var authHeader = httpContext.Request.Headers.Authorization.FirstOrDefault();
        if (authHeader is not null && authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            var bearer = authHeader["Bearer ".Length..].Trim();
            if (!string.IsNullOrWhiteSpace(bearer))
                return bearer;
        }

        // 3. Cookie
        if (httpContext.Request.Cookies.TryGetValue(cookieName, out var cookieToken)
            && !string.IsNullOrWhiteSpace(cookieToken))
        {
            return cookieToken;
        }

        return null;
    }

    private static bool VerifyCallbackSignature(
        CallbackRequest body,
        string normalizedIcan,
        string sessionId,
        string coreId,
        HttpContext httpContext,
        ILogger logger)
    {
        if (string.IsNullOrWhiteSpace(body.Signature))
        {
            logger.LogWarning("Callback missing required signature. ICAN={Ican}", normalizedIcan);
            return false;
        }

        var sigBytes = Ed448Verifier.HexToBytes(body.Signature);
        if (sigBytes is null || sigBytes.Length != Ed448Verifier.SignatureLengthBytes)
        {
            logger.LogWarning("Callback invalid signature format. ICAN={Ican}", normalizedIcan);
            return false;
        }

        byte[]? publicKey = ResolvePublicKey(normalizedIcan, httpContext);
        if (publicKey is null)
        {
            logger.LogWarning("Callback public key not available. ICAN={Ican}", normalizedIcan);
            return false;
        }

        var message = Ed448Verifier.BuildCallbackMessage(sessionId, coreId);
        if (!Ed448Verifier.Verify(publicKey, sigBytes, message))
        {
            logger.LogWarning("Callback signature verification failed. ICAN={Ican}, IP={IP}",
                normalizedIcan, httpContext.Connection.RemoteIpAddress);
            return false;
        }

        return true;
    }

    private static byte[]? ResolvePublicKey(string normalizedIcan, HttpContext httpContext)
    {
        if (IcanUtility.IsLongForm(normalizedIcan))
        {
            var bban = IcanUtility.ExtractBban(normalizedIcan)!;
            return Ed448Verifier.HexToBytes(bban[..114]);
        }

        var pubKeyHeader = httpContext.Request.Headers["X-Public-Key"].FirstOrDefault();
        if (pubKeyHeader is not null)
            return Ed448Verifier.ParsePublicKey(pubKeyHeader);

        return null;
    }

    #endregion
}
