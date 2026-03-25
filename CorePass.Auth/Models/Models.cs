using System.Text.Json;
using System.Text.Json.Serialization;

namespace CorePass.Auth;

#region Domain Models

/// <summary>
/// Represents a pending login challenge stored server-side.
/// </summary>
public sealed class ChallengeEntry
{
    public required string ChallengeId { get; init; }

    /// <summary>Session token embedded in the login URI (used for the CorePass callback).</summary>
    public required string SessionToken { get; init; }

    /// <summary>Authenticated session token created after successful callback (returned to polling client).</summary>
    public string? AuthToken { get; set; }

    public ChallengeStatus Status { get; set; } = ChallengeStatus.Pending;
    public string? CoreId { get; set; }
    public string? Ican { get; set; }
    public string? Name { get; set; }
    public string? Reason { get; set; }
    public DateTimeOffset CreatedAt { get; init; }
    public DateTimeOffset ExpiresAt { get; init; }
}

/// <summary>
/// Represents an authenticated session stored server-side.
/// </summary>
public sealed class SessionEntry
{
    public required string Token { get; init; }
    public required string CoreId { get; init; }
    public required string Ican { get; init; }
    public required string Name { get; init; }
    public DateTimeOffset CreatedAt { get; init; }
    public DateTimeOffset ExpiresAt { get; init; }
}

public enum ChallengeStatus
{
    Pending,
    Authenticated,
    Rejected,
    Expired
}

#endregion

#region API Request DTOs

public sealed class ChallengeRequest
{
    // Currently no fields required; included for future extensibility.
}

/// <summary>
/// Custom converter handles both "coreID" and "coreId" JSON field names
/// without causing a case-insensitive property name collision.
/// </summary>
[JsonConverter(typeof(CallbackRequestConverter))]
public sealed class CallbackRequest
{
    public string? Session { get; set; }
    public string? SessionId { get; set; }
    public string? CoreID { get; set; }
    public string? Signature { get; set; }

    /// <summary>Resolved session value (prefers "session" over "sessionId").</summary>
    [JsonIgnore]
    public string? ResolvedSession => Session ?? SessionId;

    /// <summary>Resolved coreId value.</summary>
    [JsonIgnore]
    public string? ResolvedCoreId => CoreID;
}

public sealed class CallbackRequestConverter : JsonConverter<CallbackRequest>
{
    public override CallbackRequest Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        var result = new CallbackRequest();
        using var doc = JsonDocument.ParseValue(ref reader);
        foreach (var prop in doc.RootElement.EnumerateObject())
        {
            switch (prop.Name)
            {
                case "session":
                    result.Session = prop.Value.GetString();
                    break;
                case "sessionId":
                    result.SessionId = prop.Value.GetString();
                    break;
                case "coreID":
                case "coreId":
                    result.CoreID = prop.Value.GetString();
                    break;
                case "signature":
                    result.Signature = prop.Value.GetString();
                    break;
            }
        }
        return result;
    }

    public override void Write(Utf8JsonWriter writer, CallbackRequest value, JsonSerializerOptions options)
    {
        writer.WriteStartObject();
        if (value.Session is not null) writer.WriteString("session", value.Session);
        if (value.SessionId is not null) writer.WriteString("sessionId", value.SessionId);
        if (value.CoreID is not null) writer.WriteString("coreId", value.CoreID);
        if (value.Signature is not null) writer.WriteString("signature", value.Signature);
        writer.WriteEndObject();
    }
}

public sealed class PasskeyDataRequest
{
    [JsonPropertyName("coreId")]
    public string? CoreId { get; set; }

    [JsonPropertyName("credentialId")]
    public string? CredentialId { get; set; }

    /// <summary>Timestamp in microseconds.</summary>
    [JsonPropertyName("timestamp")]
    public long Timestamp { get; set; }

    [JsonPropertyName("userData")]
    public object? UserData { get; set; }
}

#endregion

#region API Response DTOs

public sealed class ChallengeResponse
{
    [JsonPropertyName("challengeId")]
    public required string ChallengeId { get; init; }

    [JsonPropertyName("loginUri")]
    public required string LoginUri { get; init; }

    [JsonPropertyName("mobileUri")]
    public required string MobileUri { get; init; }

    [JsonPropertyName("appLinkUri")]
    public required string AppLinkUri { get; init; }

    [JsonPropertyName("expiresIn")]
    public required int ExpiresIn { get; init; }

    [JsonPropertyName("qrDataUrl")]
    public string? QrDataUrl { get; init; }
}

public sealed class ChallengeStatusResponse
{
    [JsonPropertyName("status")]
    public required string Status { get; init; }

    [JsonPropertyName("token")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Token { get; init; }

    [JsonPropertyName("ican")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Ican { get; init; }

    [JsonPropertyName("name")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Name { get; init; }

    [JsonPropertyName("reason")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Reason { get; init; }
}

public sealed class SessionResponse
{
    [JsonPropertyName("authenticated")]
    public required bool Authenticated { get; init; }

    [JsonPropertyName("coreId")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? CoreId { get; init; }

    [JsonPropertyName("ican")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Ican { get; init; }

    [JsonPropertyName("name")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Name { get; init; }
}

public sealed class ErrorResponse
{
    [JsonPropertyName("error")]
    public required string Error { get; init; }
}

public sealed class PasskeyDataResponse
{
    [JsonPropertyName("valid")]
    public required bool Valid { get; init; }

    [JsonPropertyName("coreId")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? CoreId { get; init; }

    [JsonPropertyName("credentialId")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? CredentialId { get; init; }

    [JsonPropertyName("timestamp")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public long Timestamp { get; init; }
}

#endregion
