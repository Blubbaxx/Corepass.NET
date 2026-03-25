namespace CorePass.Auth;

/// <summary>
/// Pluggable store interface for CorePass challenge and session entries.
/// Implementations must handle TTL expiration.
/// </summary>
public interface ICorePassStore
{
    // Challenge operations
    Task SaveChallengeAsync(ChallengeEntry challenge, CancellationToken ct = default);
    Task<ChallengeEntry?> GetChallengeAsync(string challengeId, CancellationToken ct = default);
    Task UpdateChallengeAsync(ChallengeEntry challenge, CancellationToken ct = default);
    Task DeleteChallengeAsync(string challengeId, CancellationToken ct = default);

    // Session operations
    Task SaveSessionAsync(SessionEntry session, CancellationToken ct = default);
    Task<SessionEntry?> GetSessionByTokenAsync(string token, CancellationToken ct = default);
    Task DeleteSessionByTokenAsync(string token, CancellationToken ct = default);

    // Passkey replay protection
    Task<bool> HasSignatureHashAsync(string hash, CancellationToken ct = default);
    Task SaveSignatureHashAsync(string hash, TimeSpan ttl, CancellationToken ct = default);
}
