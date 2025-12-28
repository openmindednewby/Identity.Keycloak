# NuGet Package Development Guide

Quick guide for debugging and publishing this NuGet package.

## Prerequisites

- .NET 8.0 SDK or later
- NuGet.org account with API key (for publishing)
- Git

## Project Structure

```
PackageName/
├── src/PackageName/          # Source code
│   ├── *.cs                  # Implementation files
│   └── PackageName.csproj    # Project file
├── Directory.Build.props      # Shared build configuration
├── PackageName.sln           # Solution file
├── README.md                 # Package documentation
├── LICENSE                   # MIT License
└── BUILD.md                  # Detailed build instructions
```

## Quick Start

### 1. Build the Package

```bash
# Clean previous builds
rm -rf bin obj artifacts

# Build in Release mode
dotnet build -c Release

# Create NuGet package
dotnet pack -c Release -o ./artifacts
```

The `.nupkg` file will be in the `artifacts/` folder.

### 2. Test Locally

**Option A: Use Local Folder as NuGet Source**

```bash
# Add local folder as NuGet source
dotnet nuget add source C:\path\to\artifacts --name LocalPackages

# In your test project
dotnet add package PackageName --version 1.0.x --source LocalPackages
```

**Option B: Install Directly**

```bash
# In your test project directory
dotnet add package PackageName --source C:\path\to\artifacts
```

### 3. Debug the Package

#### Method 1: Reference the Project Directly (Easiest)

In your test project's `.csproj`:

```xml
<ItemGroup>
  <!-- Comment out the PackageReference -->
  <!-- <PackageReference Include="PackageName" Version="1.0.0" /> -->

  <!-- Add ProjectReference instead -->
  <ProjectReference Include="..\..\PackageName\src\PackageName\PackageName.csproj" />
</ItemGroup>
```

Now you can:
- Set breakpoints in the package source code
- Step through the code
- Make changes and see them immediately

#### Method 2: Include Symbols

If you must use the NuGet package:

1. Build with symbols:
   ```bash
   dotnet pack -c Debug -o ./artifacts
   ```

2. Enable symbol server in Visual Studio:
   - Tools → Options → Debugging → Symbols
   - Add: `C:\path\to\artifacts`

3. Enable "Just My Code":
   - Tools → Options → Debugging → General
   - Uncheck "Enable Just My Code"

## Publishing to NuGet.org

### Prerequisites

1. **NuGet.org Account**: Create at https://www.nuget.org
2. **API Key**: Generate at https://www.nuget.org/account/apikeys
   - Name: "PackageName Publishing"
   - Expiration: 365 days
   - Scopes: "Push"

### Publish Steps

1. **Clean and Build**
   ```bash
   rm -rf artifacts bin obj src/*/bin src/*/obj
   dotnet pack -c Release -o ./artifacts
   ```

2. **Verify Package Contents**
   ```bash
   # Extract and inspect
   unzip -l artifacts/PackageName.1.0.x.nupkg
   ```

3. **Publish to NuGet.org**
   ```bash
   dotnet nuget push ./artifacts/PackageName.1.0.x.nupkg \
     --api-key YOUR_API_KEY \
     --source https://api.nuget.org/v3/index.json
   ```

4. **Wait for Indexing**
   - New packages take 10-30 minutes to be indexed
   - Check status: https://www.nuget.org/packages/PackageName

### Publish All Packages (Multi-Package Repository)

If this is part of a multi-package repository, use the provided scripts:

```powershell
# Publish all packages
.\publish-all-to-nuget.ps1 -Version "1.0.1"

# Push to GitHub
.\push-all.ps1 yourusername
```

## Version Bumping

### Update Version

Edit `Directory.Build.props`:

```xml
<Version>1.0.2</Version>
<AssemblyVersion>1.0.2.0</AssemblyVersion>
<FileVersion>1.0.2.0</FileVersion>
```

### Semantic Versioning Guide

- **Patch** (1.0.x): Bug fixes, no breaking changes
- **Minor** (1.x.0): New features, no breaking changes
- **Major** (x.0.0): Breaking changes

## Common Issues

### Issue: "Package already exists"

**Solution**: Increment the version number. NuGet.org doesn't allow overwriting versions.

### Issue: "Unable to find package"

**Causes**:
1. Package still indexing (wait 10-30 minutes)
2. Wrong package name/version
3. Typo in package ID

**Solution**:
```bash
# Clear NuGet cache
dotnet nuget locals all --clear

# Check package exists
https://www.nuget.org/packages/PackageName
```

### Issue: Dependencies not resolving

**Cause**: Dependent packages not yet indexed on NuGet.org

**Solution**: Wait for all dependency packages to be indexed, then republish.

### Issue: Symbols not loading for debugging

**Solution**:
1. Build in Debug mode: `dotnet pack -c Debug`
2. Check `.snupkg` file exists in artifacts
3. Add symbol source in Visual Studio
4. Disable "Just My Code"

## Best Practices

### Before Publishing

- ✅ Update version number
- ✅ Update CHANGELOG.md (if exists)
- ✅ Run all tests: `dotnet test`
- ✅ Build in Release mode
- ✅ Review package contents
- ✅ Test in a sample project
- ✅ Commit changes to Git
- ✅ Create Git tag: `git tag v1.0.x`

### Package Quality

- ✅ Include XML documentation (`<GenerateDocumentationFile>true</GenerateDocumentationFile>`)
- ✅ Include README.md in package
- ✅ Use semantic versioning
- ✅ Include LICENSE file
- ✅ Set correct package metadata (description, tags, repository URL)
- ✅ Enable source link for debugging
- ✅ Include symbol packages (.snupkg)

### Security

- ⚠️ **NEVER** commit API keys to Git
- ⚠️ Use environment variables or secure key storage
- ⚠️ Rotate API keys regularly
- ⚠️ Use minimal scope API keys (Push only)

## Useful Commands

```bash
# List all NuGet sources
dotnet nuget list source

# Add NuGet source
dotnet nuget add source https://api.nuget.org/v3/index.json --name NuGetOfficial

# Remove NuGet source
dotnet nuget remove source LocalPackages

# Clear all NuGet caches
dotnet nuget locals all --clear

# List installed packages in project
dotnet list package

# Update package in project
dotnet add package PackageName --version 1.0.2

# Remove package from project
dotnet remove package PackageName

# Search for packages
dotnet package search PackageName

# Show package details
dotnet package show PackageName
```

## Troubleshooting Builds

### Clean Everything

```bash
# Clean solution
dotnet clean

# Remove all bin/obj folders
find . -type d -name "bin" -o -name "obj" | xargs rm -rf

# Clear NuGet cache
dotnet nuget locals all --clear

# Restore packages
dotnet restore

# Rebuild
dotnet build -c Release
```

### Common Build Errors

**Error: "Project file does not exist"**
- Check .sln file has correct paths
- Ensure .csproj files are in correct locations

**Error: "Unable to find package X"**
- Run `dotnet restore`
- Check package name/version in .csproj
- Clear NuGet cache

**Error: "Duplicate PackageReference"**
- Check for Central Package Management (CPM)
- Remove version from `<PackageReference>` if using CPM
- Version should be in `Directory.Packages.props`

## Resources

- **NuGet Documentation**: https://docs.microsoft.com/en-us/nuget/
- **Package Publishing**: https://docs.microsoft.com/en-us/nuget/create-packages/publish-a-package
- **Semantic Versioning**: https://semver.org/
- **Package Icon Guidelines**: https://docs.microsoft.com/en-us/nuget/create-packages/package-icon-guidelines

## Quick Reference Card

| Task | Command |
|------|---------|
| Build | `dotnet build -c Release` |
| Pack | `dotnet pack -c Release -o ./artifacts` |
| Test locally | `dotnet add package PackageName --source ./artifacts` |
| Publish | `dotnet nuget push ./artifacts/*.nupkg --api-key KEY --source https://api.nuget.org/v3/index.json` |
| Clean | `dotnet clean && rm -rf artifacts bin obj` |
| Clear cache | `dotnet nuget locals all --clear` |

## Support

For issues or questions:
- GitHub Issues: https://github.com/yourusername/PackageName/issues
- NuGet Gallery: https://www.nuget.org/packages/PackageName
- Documentation: See BUILD.md for detailed instructions

---

**License**: MIT

**Last Updated**: December 2025
