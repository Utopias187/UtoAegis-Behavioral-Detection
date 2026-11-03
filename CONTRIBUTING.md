# Contributing

UtoAegis is proprietary software and is not accepting unsolicited code
contributions. Do not submit source, patches, or copied third-party material
without a separate written ownership and licensing agreement with Francisco
Jaimes.

Authorized development should use a focused branch and pull request. Each
change must preserve the documented security boundaries and pass:

```powershell
dotnet restore UtoAegis.slnx --locked-mode
dotnet build UtoAegis.slnx --no-restore --configuration Release
dotnet format UtoAegis.slnx --verify-no-changes --no-restore
dotnet test UtoAegis.slnx --no-build --configuration Release
dotnet list UtoAegis.slnx package --vulnerable --include-transitive --no-restore
```

Security findings should be reported through `SECURITY.md`, not through a
public issue or pull request.
