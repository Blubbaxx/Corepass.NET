using System.Security.Cryptography;

namespace CorePass.Auth;

/// <summary>
/// Cryptographic helper for generating challenge IDs, session tokens, and QR data URLs.
/// </summary>
public static class CryptoHelper
{
    /// <summary>
    /// Generate a cryptographically random hex string (16 bytes = 32 hex chars) for challenge IDs.
    /// </summary>
    public static string GenerateChallengeId()
    {
        return RandomNumberGenerator.GetHexString(32, lowercase: true);
    }

    /// <summary>
    /// Generate a cryptographically random hex string (32 bytes = 64 hex chars) for session tokens.
    /// </summary>
    public static string GenerateSessionToken()
    {
        return RandomNumberGenerator.GetHexString(64, lowercase: true);
    }
}
