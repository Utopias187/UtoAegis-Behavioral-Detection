# Third-party notices

UtoAegis is proprietary software, but it depends on separately licensed
third-party components. Those components are not owned by Francisco Jaimes and
are not covered by the UtoAegis Proprietary Source License.

The committed NuGet lock files are the authoritative record of the exact
dependency graph. The principal dependency families in the current graph are:

| Component family | Current version | License |
| --- | --- | --- |
| Microsoft.Data.Sqlite and Microsoft.Data.Sqlite.Core | 10.0.12 | MIT |
| Microsoft.Extensions runtime packages | 10.0.13 | MIT |
| System.Diagnostics.EventLog and System.ServiceProcess.ServiceController | 10.0.13 | MIT |
| System.IO.FileSystem.AccessControl | 5.0.0 | MIT |
| SQLitePCLRaw packages | 2.1.12 | Apache License 2.0 |
| SQLite native library bundled by SQLitePCLRaw | bundled dependency | Public domain |
| MSTest and Microsoft testing-platform packages | locked versions | Primarily MIT; see each package |
| Microsoft.Testing.Extensions.CodeCoverage | 18.11.0 | Microsoft .NET Library license |

License information and required notices distributed inside each NuGet package
remain controlling. Redistributed binaries must retain all notices required by
those packages. Useful upstream references include:

- Microsoft .NET license information: <https://github.com/dotnet/runtime/blob/main/LICENSE.TXT>
- SQLitePCLRaw: <https://github.com/ericsink/SQLitePCL.raw>
- Apache License 2.0: <https://www.apache.org/licenses/LICENSE-2.0>
- SQLite public-domain dedication: <https://www.sqlite.org/copyright.html>
- MSTest: <https://github.com/microsoft/testfx>

Test and development dependencies do not form part of the normal UtoAegis
runtime distribution unless they are expressly included in a particular build.
