using QRCoder;

namespace CorePass.Auth;

/// <summary>
/// Generates QR code data URLs for CorePass login URIs using QRCoder.
/// </summary>
public static class QrCodeHelper
{
    /// <summary>
    /// Generate a data:image/png;base64 QR code for the given content.
    /// </summary>
    public static string GenerateDataUrl(string content)
    {
        using var generator = new QRCodeGenerator();
        using var data = generator.CreateQrCode(content, QRCodeGenerator.ECCLevel.M);
        using var code = new PngByteQRCode(data);
        var bytes = code.GetGraphic(5);
        var base64 = Convert.ToBase64String(bytes);
        return $"data:image/png;base64,{base64}";
    }
}
