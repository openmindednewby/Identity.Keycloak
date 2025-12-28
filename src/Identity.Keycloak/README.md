# OnlineMenu.Identity.Keycloak

Keycloak implementation of the OnlineMenu.Identity.Abstractions package.

## Overview

This package provides a production-ready Keycloak identity provider implementation with support for:
- Username/Password authentication (Direct Grant/ROPC)
- Phone OTP authentication
- Email OTP authentication
- Token refresh and revocation
- User information retrieval

## Installation

```bash
dotnet add package OnlineMenu.Identity.Keycloak
```

## Prerequisites

- Keycloak server (v20.0+)
- Configured realm and client
- Client with Direct Access Grants enabled

## Configuration

### appsettings.json

```json
{
  "Keycloak": {
    "Authority": "https://identity.dloizides.com/realms/OnlineMenu",
    "ClientId": "online-menu-api",
    "ClientSecret": "your-client-secret",
    "RequireHttpsMetadata": true
  },
  "IdentityProvider": {
    "ProviderType": "Keycloak",
    "DefaultAuthMethod": "UsernamePassword",
    "EnableOtpAuth": true,
    "OtpCodeLength": 6,
    "OtpExpiryMinutes": 5,
    "MaxOtpAttempts": 3,
    "DevelopmentMode": false
  }
}
```

### Keycloak Client Setup

1. Create a new client in Keycloak Admin Console
2. Set **Client Protocol**: `openid-connect`
3. Set **Access Type**: `confidential`
4. Enable **Direct Access Grants** (for password flow)
5. Enable **Service Accounts** (for OTP flow)
6. Generate and save the **Client Secret**

## Usage

### Register in Dependency Injection

```csharp
using OnlineMenu.Identity.Keycloak.Extensions;

var builder = WebApplication.CreateBuilder(args);

// Register Keycloak identity provider
builder.Services.AddKeycloakIdentityProvider(builder.Configuration);

// Or with a notification service for OTP
builder.Services.AddKeycloakIdentityProvider<TwilioNotificationService>(builder.Configuration);

var app = builder.Build();
```

### Use in Your Code

```csharp
using OnlineMenu.Identity.Abstractions.Abstractions;
using OnlineMenu.Identity.Abstractions.Models;

public class AuthService
{
    private readonly IIdentityProvider _identityProvider;

    public AuthService(IIdentityProvider identityProvider)
    {
        _identityProvider = identityProvider;
    }

    // Username/Password authentication
    public async Task<AuthenticationResult> LoginAsync(string username, string password)
    {
        var request = new AuthenticationRequest
        {
            AuthMethod = AuthMethod.UsernamePassword,
            Username = username,
            Password = password
        };

        return await _identityProvider.AuthenticateAsync(request);
    }

    // Phone OTP authentication
    public async Task<OtpResult> SendOtpAsync(string phoneNumber, Guid tenantId)
    {
        var request = new OtpRequest
        {
            Identifier = phoneNumber,
            Type = OtpType.Phone,
            TenantId = tenantId
        };

        return await _identityProvider.SendOtpAsync(request);
    }

    public async Task<AuthenticationResult> VerifyOtpAsync(
        string phoneNumber,
        string code,
        Guid tenantId)
    {
        return await _identityProvider.VerifyOtpAsync(phoneNumber, code, tenantId);
    }

    // Token refresh
    public async Task<AuthenticationResult> RefreshTokenAsync(string refreshToken)
    {
        return await _identityProvider.RefreshTokenAsync(refreshToken);
    }

    // Logout
    public async Task<bool> LogoutAsync(string token)
    {
        return await _identityProvider.RevokeTokenAsync(token);
    }
}
```

## Authentication Flows

### Username/Password Flow

```
Client → IIdentityProvider.AuthenticateAsync()
         ↓
     KeycloakTokenService.AuthenticateWithPasswordAsync()
         ↓
     POST /protocol/openid-connect/token
     grant_type=password
     &username={username}
     &password={password}
         ↓
     Keycloak validates and returns tokens
         ↓
     Return AuthenticationResult with tokens
```

### Phone OTP Flow

```
Client → IIdentityProvider.SendOtpAsync()
         ↓
     OtpService.GenerateCode()
         ↓
     OtpService.StoreCodeAsync()
         ↓
     INotificationService.SendSmsAsync()
         ↓
     Twilio/SMS provider sends SMS

User receives SMS with code

Client → IIdentityProvider.VerifyOtpAsync()
         ↓
     OtpService.ValidateCodeAsync()
         ↓
     KeycloakTokenService.ExchangeForTokenAsync()
         ↓
     POST /protocol/openid-connect/token
     grant_type=client_credentials
         ↓
     Return AuthenticationResult with tokens
```

## Features

### Token Management
- Automatic token refresh
- Token revocation (logout)
- Secure token storage recommendations

### OTP Support
- Configurable code length (4-10 digits)
- Configurable expiry time
- Rate limiting support
- Development mode (returns code in response)

### Error Handling
- Comprehensive exception hierarchy
- Detailed error codes
- User-friendly error messages

### Multi-Tenant
- Tenant-scoped OTP codes
- Tenant-specific configuration support

## Security Considerations

### Direct Grant (ROPC) Flow
The Resource Owner Password Credentials flow is used for username/password authentication. While this is less secure than Authorization Code + PKCE, it's acceptable for:
- First-party applications (your own app)
- Embedded login scenarios
- Mobile apps with secure storage

### OTP Security
- Codes expire after configured time
- Codes can only be used once
- Failed attempts tracked
- Rate limiting recommended

### Token Storage
Always store tokens securely:
- Use `expo-secure-store` for React Native
- Use `HttpOnly` cookies for web
- Never store in localStorage

## Troubleshooting

### "Invalid credentials" error
- Verify username and password are correct
- Ensure user exists in Keycloak
- Check user is enabled in Keycloak

### "Direct Access Grants not enabled"
- Go to Keycloak Admin Console
- Select your client
- Enable "Direct Access Grants Enabled"
- Save changes

### "OTP not sending"
- Verify notification service is registered
- Check Twilio credentials
- Verify phone number format

## Advanced Configuration

### Custom OTP Service

You can implement your own OTP storage (e.g., database-backed):

```csharp
public class DatabaseOtpService : IOtpService
{
    private readonly AppDbContext _dbContext;

    public DatabaseOtpService(AppDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public async Task StoreCodeAsync(/* ... */)
    {
        var otpCode = new OtpCode
        {
            Identifier = identifier,
            Code = code,
            ExpiresAt = DateTime.UtcNow.AddMinutes(expiryMinutes),
            TenantId = tenantId
        };

        _dbContext.OtpCodes.Add(otpCode);
        await _dbContext.SaveChangesAsync(cancellationToken);
    }

    // ... other methods
}

// Register in DI
services.AddSingleton<IOtpService, DatabaseOtpService>();
```

### Custom Notification Service

```csharp
public class TwilioNotificationService : INotificationService
{
    private readonly TwilioClient _twilioClient;

    public async Task<bool> SendSmsAsync(
        string phoneNumber,
        string message,
        CancellationToken cancellationToken)
    {
        await _twilioClient.SendMessageAsync(phoneNumber, message);
        return true;
    }

    // ... email implementation
}
```

## Testing

Unit tests are provided in the `OnlineMenu.Identity.Keycloak.Tests` project.

```bash
dotnet test
```

## License

MIT

## Support

For issues or questions:
- GitHub Issues: [OnlineMenuSaaS/Identity](https://github.com/your-org/OnlineMenuSaaS)
- Documentation: [See main README](../../README.md)
