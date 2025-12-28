using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OnlineMenu.Identity.Abstractions.Abstractions;
using OnlineMenu.Identity.Abstractions.Configuration;
using OnlineMenu.Identity.Abstractions.Exceptions;
using OnlineMenu.Identity.Abstractions.Models;
using OnlineMenu.Identity.Keycloak.Configuration;
using OnlineMenu.Identity.Keycloak.Services;

namespace OnlineMenu.Identity.Keycloak;

/// <summary>
/// Keycloak implementation of IIdentityProvider
/// Supports username/password (ROPC) and custom OTP flows
/// </summary>
public class KeycloakIdentityProvider : IIdentityProvider
{
  private readonly KeycloakTokenService _tokenService;
  private readonly IOtpService _otpService;
  private readonly INotificationService _notificationService;
  private readonly IdentityProviderOptions _identityOptions;
  private readonly ILogger<KeycloakIdentityProvider> _logger;

  public KeycloakIdentityProvider(
    KeycloakTokenService tokenService,
    IOtpService otpService,
    INotificationService notificationService,
    IOptions<IdentityProviderOptions> identityOptions,
    ILogger<KeycloakIdentityProvider> logger)
  {
    _tokenService = tokenService;
    _otpService = otpService;
    _notificationService = notificationService;
    _identityOptions = identityOptions.Value;
    _logger = logger;
  }

  /// <summary>
  /// Authenticate user based on the specified method
  /// </summary>
  public async Task<AuthenticationResult> AuthenticateAsync(
    AuthenticationRequest request,
    CancellationToken cancellationToken = default)
  {
    try
    {
      return request.AuthMethod switch
      {
        AuthMethod.UsernamePassword => await AuthenticateWithPasswordAsync(request, cancellationToken),
        AuthMethod.PhoneOtp => await AuthenticateWithOtpAsync(request, cancellationToken),
        AuthMethod.EmailOtp => await AuthenticateWithOtpAsync(request, cancellationToken),
        _ => AuthenticationResult.Failure(
          "Authentication method not supported",
          "UNSUPPORTED_AUTH_METHOD")
      };
    }
    catch (InvalidCredentialsException ex)
    {
      _logger.LogWarning(ex, "Authentication failed for {Method}", request.AuthMethod);
      return AuthenticationResult.Failure(ex.Message, ex.ErrorCode ?? "AUTH_FAILED");
    }
    catch (Exception ex)
    {
      _logger.LogError(ex, "Unexpected error during authentication");
      return AuthenticationResult.Failure(
        "An error occurred during authentication",
        "AUTH_ERROR");
    }
  }

  /// <summary>
  /// Refresh access token using refresh token
  /// </summary>
  public async Task<AuthenticationResult> RefreshTokenAsync(
    string refreshToken,
    CancellationToken cancellationToken = default)
  {
    try
    {
      var response = await _tokenService.RefreshTokenAsync(refreshToken, cancellationToken);

      return AuthenticationResult.Success(
        response.AccessToken!,
        response.RefreshToken ?? refreshToken,
        response.ExpiresIn,
        idToken: response.IdentityToken);
    }
    catch (Exception ex)
    {
      _logger.LogError(ex, "Token refresh failed");
      return AuthenticationResult.Failure("Failed to refresh token", "REFRESH_FAILED");
    }
  }

  /// <summary>
  /// Revoke access or refresh token
  /// </summary>
  public async Task<bool> RevokeTokenAsync(
    string token,
    CancellationToken cancellationToken = default)
  {
    try
    {
      return await _tokenService.RevokeTokenAsync(token, cancellationToken);
    }
    catch (Exception ex)
    {
      _logger.LogError(ex, "Token revocation failed");
      return false;
    }
  }

  /// <summary>
  /// Get user information from access token
  /// </summary>
  public async Task<UserInfo?> GetUserInfoAsync(
    string accessToken,
    CancellationToken cancellationToken = default)
  {
    try
    {
      return await _tokenService.GetUserInfoAsync(accessToken, cancellationToken);
    }
    catch (Exception ex)
    {
      _logger.LogError(ex, "Failed to get user info");
      return null;
    }
  }

  /// <summary>
  /// Send OTP code via SMS or Email
  /// </summary>
  public async Task<OtpResult> SendOtpAsync(
    OtpRequest request,
    CancellationToken cancellationToken = default)
  {
    try
    {
      // Generate OTP code
      var codeLength = _identityOptions.OtpCodeLength;
      var code = _otpService.GenerateCode(codeLength);

      // Store in database/memory
      var expiryMinutes = _identityOptions.OtpExpiryMinutes;
      await _otpService.StoreCodeAsync(
        request.Identifier,
        code,
        request.TenantId ?? Guid.Empty,
        expiryMinutes,
        cancellationToken);

      // Send via SMS or Email
      bool sent = false;
      if (request.Type == OtpType.Sms)
      {
        var message = request.MessageTemplate ?? $"Your verification code is: {code}";
        sent = await _notificationService.SendSmsAsync(
          request.Identifier,
          message,
          cancellationToken);
      }
      else if (request.Type == OtpType.Email)
      {
        var subject = "Your Verification Code";
        var body = request.MessageTemplate ?? $"Your verification code is: {code}";
        sent = await _notificationService.SendEmailAsync(
          request.Identifier,
          subject,
          body,
          cancellationToken);
      }

      // In development mode, return the code in response
      var returnCode = _identityOptions.DevelopmentMode ? code : null;

      return new OtpResult
      {
        IsSuccessful = true,
        ExpiresIn = expiryMinutes * 60, // Convert to seconds
        Code = returnCode
      };
    }
    catch (Exception ex)
    {
      _logger.LogError(ex, "Failed to send OTP to {Identifier}", request.Identifier);
      return new OtpResult
      {
        IsSuccessful = false,
        ErrorMessage = "Failed to send verification code"
      };
    }
  }

  /// <summary>
  /// Verify OTP code and authenticate user
  /// </summary>
  public async Task<AuthenticationResult> VerifyOtpAsync(
    string identifier,
    string code,
    Guid? tenantId = null,
    CancellationToken cancellationToken = default)
  {
    try
    {
      // Validate OTP code
      var isValid = await _otpService.ValidateCodeAsync(
        identifier,
        code,
        tenantId ?? Guid.Empty,
        cancellationToken);

      if (!isValid)
      {
        return AuthenticationResult.Failure(
          "Invalid or expired verification code",
          "INVALID_OTP");
      }

      // Mark as used
      await _otpService.MarkAsUsedAsync(identifier, code, tenantId ?? Guid.Empty, cancellationToken);

      // TODO: Create or link user in Keycloak based on phone/email
      // For now, return a placeholder token
      // In production, you would:
      // 1. Check if user exists in Keycloak by phone/email
      // 2. If not, create user
      // 3. Get tokens using admin API or custom grant

      _logger.LogWarning(
        "OTP verified for {Identifier} but token generation not implemented. " +
        "Implement Keycloak user lookup/creation logic.",
        identifier);

      return AuthenticationResult.Failure(
        "OTP authentication requires additional Keycloak configuration",
        "NOT_IMPLEMENTED");
    }
    catch (Exception ex)
    {
      _logger.LogError(ex, "OTP verification failed for {Identifier}", identifier);
      return AuthenticationResult.Failure(
        "Verification failed",
        "VERIFICATION_ERROR");
    }
  }

  /// <summary>
  /// Authenticate with username and password (ROPC/Direct Grant)
  /// </summary>
  private async Task<AuthenticationResult> AuthenticateWithPasswordAsync(
    AuthenticationRequest request,
    CancellationToken cancellationToken)
  {
    if (string.IsNullOrEmpty(request.Username) || string.IsNullOrEmpty(request.Password))
    {
      return AuthenticationResult.Failure(
        "Username and password are required",
        "INVALID_REQUEST");
    }

    var response = await _tokenService.AuthenticateWithPasswordAsync(
      request.Username,
      request.Password,
      cancellationToken);

    // Get user info
    UserInfo? userInfo = null;
    try
    {
      userInfo = await GetUserInfoAsync(response.AccessToken!, cancellationToken);
      if (userInfo == null)
      {
        _logger.LogWarning("GetUserInfoAsync returned null for access token");
      }
      else
      {
        _logger.LogInformation("Successfully retrieved user info for user {Sub} with {RoleCount} roles",
          userInfo.Sub, userInfo.Roles?.Count ?? 0);
      }
    }
    catch (Exception ex)
    {
      _logger.LogError(ex, "Failed to retrieve user info during authentication");
      // User info is optional, continue without it
    }

    return AuthenticationResult.Success(
      response.AccessToken!,
      response.RefreshToken!,
      response.ExpiresIn,
      userInfo,
      response.IdentityToken);
  }

  /// <summary>
  /// Authenticate with OTP (phone or email)
  /// </summary>
  private Task<AuthenticationResult> AuthenticateWithOtpAsync(
    AuthenticationRequest request,
    CancellationToken cancellationToken)
  {
    var identifier = request.PhoneNumber ?? request.Email;
    var code = request.OtpCode;

    if (string.IsNullOrEmpty(identifier) || string.IsNullOrEmpty(code))
    {
      return Task.FromResult(AuthenticationResult.Failure(
        "Phone number/email and OTP code are required",
        "INVALID_REQUEST"));
    }

    return VerifyOtpAsync(identifier, code, request.TenantId, cancellationToken);
  }
}
