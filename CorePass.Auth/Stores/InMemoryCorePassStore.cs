using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CorePass.Auth;

/// <summary>
/// In-memory implementation of <see cref="ICorePassStore"/> with TTL expiration,
/// periodic cleanup, and maximum entry limit (DoS mitigation).
/// </summary>
public sealed class InMemoryCorePassStore : ICorePassStore, IDisposable
{
    private readonly ConcurrentDictionary<string, ChallengeEntry> _challenges = new();
    private readonly ConcurrentDictionary<string, SessionEntry> _sessions = new();
    private readonly ConcurrentDictionary<string, DateTimeOffset> _signatureHashes = new();
    private readonly Timer _cleanupTimer;
    private readonly int _maxEntries;
    private readonly ILogger<InMemoryCorePassStore> _logger;

    public InMemoryCorePassStore(IOptions<CorePassOptions> options, ILogger<InMemoryCorePassStore> logger)
    {
        _logger = logger;
        var opts = options.Value;
        _maxEntries = opts.MaxStoreEntries;

        _cleanupTimer = new Timer(
            Cleanup,
            null,
            TimeSpan.FromSeconds(opts.CleanupIntervalSeconds),
            TimeSpan.FromSeconds(opts.CleanupIntervalSeconds));
    }

    #region Challenge Operations

    public Task SaveChallengeAsync(ChallengeEntry challenge, CancellationToken ct = default)
    {
        EnforceLimit();
        _challenges[challenge.ChallengeId] = challenge;
        return Task.CompletedTask;
    }

    public Task<ChallengeEntry?> GetChallengeAsync(string challengeId, CancellationToken ct = default)
    {
        if (_challenges.TryGetValue(challengeId, out var entry))
        {
            if (DateTimeOffset.UtcNow > entry.ExpiresAt)
            {
                entry.Status = ChallengeStatus.Expired;
                _challenges.TryRemove(challengeId, out _);
                return Task.FromResult<ChallengeEntry?>(entry);
            }
            return Task.FromResult<ChallengeEntry?>(entry);
        }
        return Task.FromResult<ChallengeEntry?>(null);
    }

    public Task UpdateChallengeAsync(ChallengeEntry challenge, CancellationToken ct = default)
    {
        _challenges[challenge.ChallengeId] = challenge;
        return Task.CompletedTask;
    }

    public Task DeleteChallengeAsync(string challengeId, CancellationToken ct = default)
    {
        _challenges.TryRemove(challengeId, out _);
        return Task.CompletedTask;
    }

    #endregion

    #region Session Operations

    public Task SaveSessionAsync(SessionEntry session, CancellationToken ct = default)
    {
        EnforceLimit();
        _sessions[session.Token] = session;
        return Task.CompletedTask;
    }

    public Task<SessionEntry?> GetSessionByTokenAsync(string token, CancellationToken ct = default)
    {
        if (_sessions.TryGetValue(token, out var entry))
        {
            if (DateTimeOffset.UtcNow > entry.ExpiresAt)
            {
                _sessions.TryRemove(token, out _);
                return Task.FromResult<SessionEntry?>(null);
            }
            return Task.FromResult<SessionEntry?>(entry);
        }
        return Task.FromResult<SessionEntry?>(null);
    }

    public Task DeleteSessionByTokenAsync(string token, CancellationToken ct = default)
    {
        _sessions.TryRemove(token, out _);
        return Task.CompletedTask;
    }

    #endregion

    #region Signature Hash (Replay Protection)

    public Task<bool> HasSignatureHashAsync(string hash, CancellationToken ct = default)
    {
        if (_signatureHashes.TryGetValue(hash, out var expiry))
        {
            if (DateTimeOffset.UtcNow > expiry)
            {
                _signatureHashes.TryRemove(hash, out _);
                return Task.FromResult(false);
            }
            return Task.FromResult(true);
        }
        return Task.FromResult(false);
    }

    public Task SaveSignatureHashAsync(string hash, TimeSpan ttl, CancellationToken ct = default)
    {
        _signatureHashes[hash] = DateTimeOffset.UtcNow.Add(ttl);
        return Task.CompletedTask;
    }

    #endregion

    private void EnforceLimit()
    {
        int total = _challenges.Count + _sessions.Count;
        if (total >= _maxEntries)
        {
            _logger.LogWarning("CorePass store limit reached ({Limit}). Rejecting new entries.", _maxEntries);
            throw new InvalidOperationException("Store capacity exceeded. Try again later.");
        }
    }

    private void Cleanup(object? state)
    {
        var now = DateTimeOffset.UtcNow;
        int removed = 0;

        foreach (var kvp in _challenges)
        {
            if (now > kvp.Value.ExpiresAt)
            {
                _challenges.TryRemove(kvp.Key, out _);
                removed++;
            }
        }

        foreach (var kvp in _sessions)
        {
            if (now > kvp.Value.ExpiresAt)
            {
                _sessions.TryRemove(kvp.Key, out _);
                removed++;
            }
        }

        foreach (var kvp in _signatureHashes)
        {
            if (now > kvp.Value)
            {
                _signatureHashes.TryRemove(kvp.Key, out _);
                removed++;
            }
        }

        if (removed > 0)
            _logger.LogDebug("CorePass store cleanup removed {Count} expired entries.", removed);
    }

    public void Dispose()
    {
        _cleanupTimer.Dispose();
    }
}
