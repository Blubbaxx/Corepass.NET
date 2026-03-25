namespace CorePass.Auth;

/// <summary>
/// ICAN normalization, whitelist checking, and name resolution utilities.
/// </summary>
public static class IcanUtility
{
    /// <summary>
    /// Normalize an ICAN: trim whitespace and convert to uppercase.
    /// </summary>
    public static string Normalize(string ican)
    {
        ArgumentNullException.ThrowIfNull(ican);
        return ican.Trim().ToUpperInvariant();
    }

    /// <summary>
    /// Check if the given ICAN is allowed by the whitelist.
    /// If allowedIcans is empty, all ICANs are allowed.
    /// Both the input and whitelist entries should be pre-normalized.
    /// </summary>
    public static bool IsAllowed(string normalizedIcan, IReadOnlyList<string> allowedIcans)
    {
        if (allowedIcans.Count == 0)
            return true;

        for (int i = 0; i < allowedIcans.Count; i++)
        {
            if (string.Equals(normalizedIcan, allowedIcans[i], StringComparison.Ordinal))
                return true;
        }

        return false;
    }

    /// <summary>
    /// Resolve a display name for the given ICAN.
    /// Checks icanNames map first; falls back to first 10 chars + "..."
    /// </summary>
    public static string ResolveName(string normalizedIcan, IReadOnlyDictionary<string, string> icanNames)
    {
        if (icanNames.TryGetValue(normalizedIcan, out var name))
            return name;

        return normalizedIcan.Length > 10
            ? string.Concat(normalizedIcan.AsSpan(0, 10), "...")
            : normalizedIcan;
    }

    /// <summary>
    /// Extract the BBAN portion from a long-form ICAN.
    /// A long-form ICAN has the format: CC + 2-digit check + BBAN (remaining chars).
    /// The BBAN for Ed448 keys is 57 bytes when decoded from hex (114 hex chars).
    /// Returns null if the ICAN is too short to contain a valid BBAN.
    /// </summary>
    public static string? ExtractBban(string normalizedIcan)
    {
        // ICAN format: 2 country chars + 2 check digits + BBAN
        if (normalizedIcan.Length <= 4)
            return null;

        return normalizedIcan[4..];
    }

    /// <summary>
    /// Determine if an ICAN is long-form (contains an embedded public key in the BBAN).
    /// Long-form BBAN for Ed448 = 114 hex chars (57 bytes).
    /// </summary>
    public static bool IsLongForm(string normalizedIcan)
    {
        var bban = ExtractBban(normalizedIcan);
        return bban is not null && bban.Length >= 114;
    }
}
