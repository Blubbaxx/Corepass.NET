using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

namespace CorePass.Auth;

/// <summary>
/// Additional cookie-setting endpoint for Blazor circuit authentication.
/// When the Login page gets the session token from polling, it navigates here
/// to set an HttpOnly cookie, then redirects to the dashboard.
/// </summary>
public static class CorePassCookieEndpoint
{
    public static void MapCorePassCookieEndpoint(this WebApplication app)
    {
        app.MapGet("/auth/set-cookie", async (
            HttpContext httpContext,
            ICorePassStore store,
            IOptions<CorePassOptions> options) =>
        {
            var token = httpContext.Request.Query["token"].FirstOrDefault();
            var returnUrl = httpContext.Request.Query["returnUrl"].FirstOrDefault() ?? "/dashboard";

            if (string.IsNullOrWhiteSpace(token))
            {
                return Results.Redirect("/login");
            }

            // Verify the token is valid
            var session = await store.GetSessionByTokenAsync(token);
            if (session is null)
            {
                return Results.Redirect("/login");
            }

            var opts = options.Value;
            httpContext.Response.Cookies.Append(opts.CookieName, token, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Path = "/",
                MaxAge = TimeSpan.FromSeconds(opts.SessionTtlSeconds)
            });

            return Results.Redirect(returnUrl);
        }).ExcludeFromDescription();
    }
}
