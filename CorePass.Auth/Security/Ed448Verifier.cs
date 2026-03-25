using System.Text;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace CorePass.Auth;

/// <summary>
/// Ed448 signature verification using BouncyCastle.
/// Assumptions:
/// - Signature is hex-encoded (114 bytes = 228 hex chars for Ed448).
/// - Public key is 57 bytes, sourced from ICAN BBAN (long-form) or X-Public-Key header.
/// - The signed message is the canonical JSON of the payload with keys sorted recursively.
/// </summary>
public static class Ed448Verifier
{
    public const int SignatureLengthBytes = 114;
    public const int PublicKeyLengthBytes = 57;

    /// <summary>
    /// Verify an Ed448 signature over the given message bytes.
    /// </summary>
    /// <param name="publicKeyBytes">57-byte Ed448 public key.</param>
    /// <param name="signatureBytes">114-byte Ed448 signature.</param>
    /// <param name="message">The message bytes that were signed.</param>
    /// <returns>True if the signature is valid.</returns>
    public static bool Verify(byte[] publicKeyBytes, byte[] signatureBytes, byte[] message)
    {
        if (publicKeyBytes.Length != PublicKeyLengthBytes)
            return false;
        if (signatureBytes.Length != SignatureLengthBytes)
            return false;

        try
        {
            var pubKey = new Ed448PublicKeyParameters(publicKeyBytes, 0);
            var verifier = new Ed448Signer([]);
            verifier.Init(false, pubKey);
            verifier.BlockUpdate(message, 0, message.Length);
            return verifier.VerifySignature(signatureBytes);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Parse a hex string to bytes. Returns null if the string is not valid hex.
    /// </summary>
    public static byte[]? HexToBytes(string hex)
    {
        if (string.IsNullOrEmpty(hex) || hex.Length % 2 != 0)
            return null;

        try
        {
            return Convert.FromHexString(hex);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Parse a public key from hex or base64 format.
    /// </summary>
    public static byte[]? ParsePublicKey(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return null;

        value = value.Trim();

        // Try hex first
        if (value.Length == PublicKeyLengthBytes * 2)
        {
            var bytes = HexToBytes(value);
            if (bytes is not null && bytes.Length == PublicKeyLengthBytes)
                return bytes;
        }

        // Try base64
        try
        {
            var bytes = Convert.FromBase64String(value);
            if (bytes.Length == PublicKeyLengthBytes)
                return bytes;
        }
        catch
        {
            // Not valid base64
        }

        return null;
    }

    /// <summary>
    /// Build the canonical message for callback signature verification.
    /// Canonical JSON of { session: sessionId, coreID: coreId } with keys sorted.
    /// </summary>
    public static byte[] BuildCallbackMessage(string sessionId, string coreId)
    {
        var dict = new SortedDictionary<string, object?>(StringComparer.Ordinal)
        {
            ["coreID"] = coreId,
            ["session"] = sessionId
        };
        var canonical = CanonicalJson.Serialize(dict);
        return Encoding.UTF8.GetBytes(canonical);
    }

    /// <summary>
    /// Build the canonical message for passkey/data signature verification.
    /// Format: "POST\n{path}\n{canonicalJson(body)}"
    /// </summary>
    public static byte[] BuildPasskeyMessage(string path, string canonicalBodyJson)
    {
        var message = $"POST\n{path}\n{canonicalBodyJson}";
        return Encoding.UTF8.GetBytes(message);
    }
}
