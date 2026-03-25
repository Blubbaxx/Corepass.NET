using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace CorePass.Auth;

/// <summary>
/// Extension-Methoden zur Registrierung der CorePass-Authentifizierung.
/// </summary>
public static class CorePassServiceExtensions
{
    /// <summary>
    /// Registriert alle CorePass-Dienste (Store, URI-Builder, Auth-Handler).
    /// </summary>
    /// <param name="services">Die Service-Collection.</param>
    /// <param name="configuration">Die App-Konfiguration (enthält den Abschnitt "CorePass").</param>
    /// <returns>Die Service-Collection für Method-Chaining.</returns>
    public static IServiceCollection AddCorePass(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        var section = configuration.GetSection(CorePassOptions.SectionName);
        services.Configure<CorePassOptions>(section);

        var options = section.Get<CorePassOptions>() ?? new CorePassOptions();

        if (options.UseDistributedCache)
        {
            services.AddSingleton<ICorePassStore, DistributedCacheCorePassStore>();
        }
        else
        {
            services.AddSingleton<ICorePassStore, InMemoryCorePassStore>();
        }

        services.AddSingleton<CorePassUriBuilder>();

        services.AddAuthentication(CorePassAuthenticationHandler.SchemeName)
            .AddScheme<CorePassAuthenticationSchemeOptions, CorePassAuthenticationHandler>(
                CorePassAuthenticationHandler.SchemeName, _ => { });

        services.AddAuthorization();

        return services;
    }

    /// <summary>
    /// Mappt alle CorePass-API-Endpunkte (/auth/*) und den Cookie-Endpunkt.
    /// </summary>
    public static WebApplication MapCorePass(this WebApplication app)
    {
        app.MapCorePassEndpoints();
        app.MapCorePassCookieEndpoint();
        return app;
    }
}
