using System.Text;
using System.Text.Json;

namespace CorePass.Auth;

/// <summary>
/// Produces canonical JSON: keys sorted recursively, no extra whitespace.
/// Used for signature verification where both parties must agree on the byte representation.
/// </summary>
public static class CanonicalJson
{
    /// <summary>
    /// Serialize an object to canonical JSON (sorted keys, compact).
    /// </summary>
    public static string Serialize(object obj)
    {
        var json = JsonSerializer.Serialize(obj);
        using var doc = JsonDocument.Parse(json);
        var sb = new StringBuilder(json.Length);
        WriteCanonical(doc.RootElement, sb);
        return sb.ToString();
    }

    /// <summary>
    /// Serialize a dictionary to canonical JSON (sorted keys, compact).
    /// </summary>
    public static string Serialize(IDictionary<string, object?> dict)
    {
        var json = JsonSerializer.Serialize(dict);
        using var doc = JsonDocument.Parse(json);
        var sb = new StringBuilder(json.Length);
        WriteCanonical(doc.RootElement, sb);
        return sb.ToString();
    }

    /// <summary>
    /// Produce canonical JSON bytes for a given JSON string (re-sorts keys).
    /// </summary>
    public static byte[] ToCanonicalBytes(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var sb = new StringBuilder(json.Length);
        WriteCanonical(doc.RootElement, sb);
        return Encoding.UTF8.GetBytes(sb.ToString());
    }

    private static void WriteCanonical(JsonElement element, StringBuilder sb)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                sb.Append('{');
                var properties = new List<JsonProperty>();
                foreach (var prop in element.EnumerateObject())
                    properties.Add(prop);

                properties.Sort((a, b) => string.Compare(a.Name, b.Name, StringComparison.Ordinal));

                for (int i = 0; i < properties.Count; i++)
                {
                    if (i > 0) sb.Append(',');
                    sb.Append('"');
                    sb.Append(JsonEncodedText.Encode(properties[i].Name).ToString());
                    sb.Append('"');
                    sb.Append(':');
                    WriteCanonical(properties[i].Value, sb);
                }
                sb.Append('}');
                break;

            case JsonValueKind.Array:
                sb.Append('[');
                int index = 0;
                foreach (var item in element.EnumerateArray())
                {
                    if (index > 0) sb.Append(',');
                    WriteCanonical(item, sb);
                    index++;
                }
                sb.Append(']');
                break;

            case JsonValueKind.String:
                sb.Append('"');
                sb.Append(JsonEncodedText.Encode(element.GetString()!).ToString());
                sb.Append('"');
                break;

            case JsonValueKind.Number:
                sb.Append(element.GetRawText());
                break;

            case JsonValueKind.True:
                sb.Append("true");
                break;

            case JsonValueKind.False:
                sb.Append("false");
                break;

            case JsonValueKind.Null:
                sb.Append("null");
                break;
        }
    }
}
