using OnlineMenu.Identity.Abstractions.Abstractions;
using System.Security.Cryptography;

namespace OnlineMenu.Identity.Keycloak.Services;

/// <summary>
/// OTP generation and validation service
/// Note: This is an in-memory implementation. For production, implement IOtpRepository to store in database.
/// </summary>
public class OtpService : IOtpService
{
    private readonly Dictionary<string, OtpEntry> _otpStore = new();
    private readonly object _lock = new();

    /// <summary>
    /// Generate a random OTP code
    /// </summary>
    public string GenerateCode(int length = 6)
    {
        if (length < 4 || length > 10)
            throw new ArgumentException("OTP length must be between 4 and 10", nameof(length));

        var code = string.Empty;
        for (int i = 0; i < length; i++)
        {
            code += RandomNumberGenerator.GetInt32(0, 10).ToString();
        }
        return code;
    }

    /// <summary>
    /// Store an OTP code for later verification
    /// </summary>
    public Task StoreCodeAsync(
        string identifier,
        string code,
        Guid tenantId,
        int expiryMinutes,
        CancellationToken cancellationToken = default)
    {
        var key = GetKey(identifier, tenantId);
        var entry = new OtpEntry
        {
            Code = code,
            ExpiresAt = DateTime.UtcNow.AddMinutes(expiryMinutes),
            Attempts = 0,
            IsUsed = false
        };

        lock (_lock)
        {
            _otpStore[key] = entry;
        }

        return Task.CompletedTask;
    }

    /// <summary>
    /// Validate an OTP code
    /// </summary>
    public Task<bool> ValidateCodeAsync(
        string identifier,
        string code,
        Guid tenantId,
        CancellationToken cancellationToken = default)
    {
        var key = GetKey(identifier, tenantId);

        lock (_lock)
        {
            if (!_otpStore.TryGetValue(key, out var entry))
                return Task.FromResult(false);

            // Check if expired
            if (DateTime.UtcNow > entry.ExpiresAt)
            {
                _otpStore.Remove(key);
                return Task.FromResult(false);
            }

            // Check if already used
            if (entry.IsUsed)
                return Task.FromResult(false);

            // Increment attempts
            entry.Attempts++;

            // Validate code
            var isValid = entry.Code == code;

            return Task.FromResult(isValid);
        }
    }

    /// <summary>
    /// Mark an OTP code as used
    /// </summary>
    public Task MarkAsUsedAsync(
        string identifier,
        string code,
        Guid tenantId,
        CancellationToken cancellationToken = default)
    {
        var key = GetKey(identifier, tenantId);

        lock (_lock)
        {
            if (_otpStore.TryGetValue(key, out var entry))
            {
                entry.IsUsed = true;
            }
        }

        return Task.CompletedTask;
    }

    private static string GetKey(string identifier, Guid tenantId)
    {
        return $"{tenantId}:{identifier}";
    }

    private class OtpEntry
    {
        public string Code { get; set; } = string.Empty;
        public DateTime ExpiresAt { get; set; }
        public int Attempts { get; set; }
        public bool IsUsed { get; set; }
    }
}
