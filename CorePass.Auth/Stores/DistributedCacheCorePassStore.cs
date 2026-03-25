using System.Text.Json;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CorePass.Auth;

/// <summary>
/// IDistributedCache-backed implementation of <see cref="ICorePassStore"/>.
/// Works with Redis, SQL Server, or any IDistributedCache provider.
/// </summary>
public sealed class DistributedCacheCorePassStore : ICorePassStore
{
    private const string ChallengePrefix = "corepass:challenge:";
    private const string SessionPrefix = "corepass:session:";
    private const string SigHashPrefix = "corepass:sighash:";

    private readonly IDistributedCache _cache;
    private readonly CorePassOptions _options;
    private readonly ILogger<DistributedCacheCorePassStore> _logger;

    public DistributedCacheCorePassStore(
        IDistributedCache cache,
        IOptions<CorePassOptions> options,
        ILogger<DistributedCacheCorePassStore> logger)
    {
        _cache = cache;
        _options = options.Value;
        _logger = logger;
    }

    #region Challenge Operations

    public async Task SaveChallengeAsync(ChallengeEntry challenge, CancellationToken ct = default)
    {
        var json = JsonSerializer.Serialize(challenge);
        var opts = new DistributedCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = TimeSpan.FromSeconds(_options.ChallengeTtlSeconds)
        };
        await _cache.SetStringAsync(ChallengePrefix + challenge.ChallengeId, json, opts, ct);
    }

    public async Task<ChallengeEntry?> GetChallengeAsync(string challengeId, CancellationToken ct = default)
    {
        var json = await _cache.GetStringAsync(ChallengePrefix + challengeId, ct);
        if (json is null) return null;

        var entry = JsonSerializer.Deserialize<ChallengeEntry>(json);
        if (entry is not null && DateTimeOffset.UtcNow > entry.ExpiresAt)
        {
            entry.Status = ChallengeStatus.Expired;
            await _cache.RemoveAsync(ChallengePrefix + challengeId, ct);
        }
        return entry;
    }

    public async Task UpdateChallengeAsync(ChallengeEntry challenge, CancellationToken ct = default)
    {
        var remaining = challenge.ExpiresAt - DateTimeOffset.UtcNow;
        if (remaining <= TimeSpan.Zero)
        {
            await _cache.RemoveAsync(ChallengePrefix + challenge.ChallengeId, ct);
            return;
        }

        var json = JsonSerializer.Serialize(challenge);
        var opts = new DistributedCacheEntryOptions
        {
            AbsoluteExpiration = challenge.ExpiresAt
        };
        await _cache.SetStringAsync(ChallengePrefix + challenge.ChallengeId, json, opts, ct);
    }

    public async Task DeleteChallengeAsync(string challengeId, CancellationToken ct = default)
    {
        await _cache.RemoveAsync(ChallengePrefix + challengeId, ct);
    }

    #endregion

    #region Session Operations

    public async Task SaveSessionAsync(SessionEntry session, CancellationToken ct = default)
    {
        var json = JsonSerializer.Serialize(session);
        var opts = new DistributedCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = TimeSpan.FromSeconds(_options.SessionTtlSeconds)
        };
        await _cache.SetStringAsync(SessionPrefix + session.Token, json, opts, ct);
    }

    public async Task<SessionEntry?> GetSessionByTokenAsync(string token, CancellationToken ct = default)
    {
        var json = await _cache.GetStringAsync(SessionPrefix + token, ct);
        if (json is null) return null;

        var entry = JsonSerializer.Deserialize<SessionEntry>(json);
        if (entry is not null && DateTimeOffset.UtcNow > entry.ExpiresAt)
        {
            await _cache.RemoveAsync(SessionPrefix + token, ct);
            return null;
        }
        return entry;
    }

    public async Task DeleteSessionByTokenAsync(string token, CancellationToken ct = default)
    {
        await _cache.RemoveAsync(SessionPrefix + token, ct);
    }

    #endregion

    #region Signature Hash (Replay Protection)

    public async Task<bool> HasSignatureHashAsync(string hash, CancellationToken ct = default)
    {
        var val = await _cache.GetStringAsync(SigHashPrefix + hash, ct);
        return val is not null;
    }

    public async Task SaveSignatureHashAsync(string hash, TimeSpan ttl, CancellationToken ct = default)
    {
        var opts = new DistributedCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = ttl
        };
        await _cache.SetStringAsync(SigHashPrefix + hash, "1", opts, ct);
    }

    #endregion
}
