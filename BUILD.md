# Building and Deploying Identity.Keycloak

This guide explains how to build, pack, and publish this NuGet package.

## 🔨 Prerequisites

- [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0) or later
- Git
- A [NuGet.org](https://www.nuget.org/) account (for publishing)

## 🏗️ Building the Package

### Clone the Repository

```bash
git clone https://github.com/yourusername/Identity.Keycloak.git
cd Identity.Keycloak
```

### Restore Dependencies

```bash
dotnet restore
```

### Build

```bash
# Debug build
dotnet build

# Release build
dotnet build -c Release
```

### Run Tests (if available)

```bash
dotnet test
```

## 📦 Creating a NuGet Package

### Pack the Package

```bash
dotnet pack -c Release -o ./artifacts
```

This creates a `.nupkg` file in the `./artifacts` folder.

### Pack with Specific Version

```bash
dotnet pack -c Release -o ./artifacts /p:Version=1.0.1
```

## 🧪 Testing Locally

Before publishing to NuGet.org, test the package locally:

### Option 1: Local NuGet Feed

```bash
# Create a local NuGet directory
mkdir C:\LocalNuGet

# Pack to local directory
dotnet pack -c Release -o C:\LocalNuGet

# Add local source (one-time setup)
dotnet nuget add source C:\LocalNuGet -n LocalFeed

# In your test project
dotnet add package Identity.Keycloak --version 1.0.0 --source LocalFeed
```

### Option 2: Direct Package Reference

In your test project's `.csproj`:

```xml
<ItemGroup>
  <PackageReference Include="Identity.Keycloak" Version="1.0.0">
    <Source>C:\path\to\Identity.Keycloak\artifacts\Identity.Keycloak.1.0.0.nupkg</Source>
  </PackageReference>
</ItemGroup>
```

## 🚀 Publishing to NuGet.org

### Step 1: Get Your API Key

1. Go to https://www.nuget.org/account/apikeys
2. Click **Create**
3. Provide a key name (e.g., "Identity.Keycloak")
4. Select **Push** scope
5. Select packages or glob pattern (e.g., `Identity.Keycloak*`)
6. Copy the generated API key

### Step 2: Publish

```bash
dotnet nuget push ./artifacts/Identity.Keycloak.1.0.0.nupkg \
  --api-key YOUR_API_KEY \
  --source https://api.nuget.org/v3/index.json
```

**Security Note:** Never commit your API key to source control!

### Step 3: Wait for Indexing

NuGet.org takes 5-15 minutes to index new packages. You can monitor the status at:
https://www.nuget.org/packages/Identity.Keycloak

## 🔄 Version Management

This package follows [Semantic Versioning](https://semver.org/):

- **Patch** (1.0.0 → 1.0.1): Bug fixes, no breaking changes
- **Minor** (1.0.0 → 1.1.0): New features, backward compatible
- **Major** (1.0.0 → 2.0.0): Breaking changes

### Updating the Version

Edit `Directory.Build.props`:

```xml
<Version>1.0.1</Version>
<AssemblyVersion>1.0.1.0</AssemblyVersion>
<FileVersion>1.0.1.0</FileVersion>
```

Then rebuild and republish.

## 🏷️ Creating a GitHub Release

After publishing to NuGet:

1. Create a Git tag:
   ```bash
   git tag -a v1.0.0 -m "Release version 1.0.0"
   git push origin v1.0.0
   ```

2. Go to GitHub → Releases → Create a new release
3. Select the tag you just created
4. Add release notes describing changes
5. Publish the release

## 🔐 Security Best Practices

### Protect Your API Key

Use environment variables or secret managers:

```bash
# Windows
$env:NUGET_API_KEY = "your-api-key"
dotnet nuget push ./artifacts/*.nupkg --api-key $env:NUGET_API_KEY --source https://api.nuget.org/v3/index.json

# Linux/Mac
export NUGET_API_KEY="your-api-key"
dotnet nuget push ./artifacts/*.nupkg --api-key $NUGET_API_KEY --source https://api.nuget.org/v3/index.json
```

### Using NuGet.config

Create a `nuget.config` in your home directory (NOT in the repository):

```xml
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <apikeys>
    <add key="https://api.nuget.org/v3/index.json" value="YOUR_API_KEY" />
  </apikeys>
</configuration>
```

Then you can push without specifying the API key:

```bash
dotnet nuget push ./artifacts/*.nupkg --source https://api.nuget.org/v3/index.json
```

## 📋 Release Checklist

Before publishing a new version:

- [ ] Update version in `Directory.Build.props`
- [ ] Update `CHANGELOG.md` (if you have one)
- [ ] Run all tests: `dotnet test`
- [ ] Build in Release mode: `dotnet build -c Release`
- [ ] Test locally with a sample project
- [ ] Pack the package: `dotnet pack -c Release`
- [ ] Review the `.nupkg` contents
- [ ] Commit changes and create a Git tag
- [ ] Push to GitHub
- [ ] Publish to NuGet.org
- [ ] Wait for indexing (5-15 minutes)
- [ ] Verify package appears on NuGet.org
- [ ] Create GitHub release with notes
- [ ] Announce the release (if applicable)

## 🔍 Inspecting Package Contents

Before publishing, inspect what's in your package:

### Using NuGet Package Explorer (Windows)

1. Download from https://github.com/NuGetPackageExplorer/NuGetPackageExplorer
2. Open your `.nupkg` file
3. Review contents, metadata, and dependencies

### Using Command Line

```bash
# Extract .nupkg (it's a zip file)
unzip Identity.Keycloak.1.0.0.nupkg -d extracted/

# View contents
ls -R extracted/
```

## 🤝 Contributing

If you're contributing to this package:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Run tests: `dotnet test`
5. Commit: `git commit -m "Add my feature"`
6. Push: `git push origin feature/my-feature`
7. Create a Pull Request

## 🐛 Troubleshooting

### "Package already exists" error

If you try to publish the same version twice:

```
error: Response status code does not indicate success: 409 (Conflict - The feed already contains 'Identity.Keycloak' version '1.0.0'.)
```

**Solution:** Increment the version number. NuGet.org doesn't allow republishing the same version.

### "Unauthorized" error

```
error: Response status code does not indicate success: 401 (Unauthorized)
```

**Solutions:**
- Verify your API key is correct
- Check that your API key has **Push** permissions
- Ensure the package name matches the glob pattern in your API key settings

### Symbols package (.snupkg) not uploading

Make sure symbols are enabled in `Directory.Build.props`:

```xml
<IncludeSymbols>true</IncludeSymbols>
<SymbolPackageFormat>snupkg</SymbolPackageFormat>
```

## 📚 Additional Resources

- [NuGet Documentation](https://docs.microsoft.com/en-us/nuget/)
- [Creating NuGet Packages](https://docs.microsoft.com/en-us/nuget/create-packages/creating-a-package)
- [Publishing to NuGet.org](https://docs.microsoft.com/en-us/nuget/nuget-org/publish-a-package)
- [Semantic Versioning](https://semver.org/)
- [.NET CLI Reference](https://docs.microsoft.com/en-us/dotnet/core/tools/)

## 💬 Support

- 🐛 **Issues**: [GitHub Issues](https://github.com/yourusername/Identity.Keycloak/issues)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/yourusername/Identity.Keycloak/discussions)
- 📦 **NuGet**: [NuGet Package Page](https://www.nuget.org/packages/Identity.Keycloak)

---

**Happy coding!** 🚀
