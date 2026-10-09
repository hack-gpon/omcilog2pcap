```
 _   _               _       ____  ____    ___   _   _ 
| | | |  __ _   ___ | | __  / ___||  _ \  / _ \ | \ | |
| |_| | / _` | / __|| |/ / | |  _ | |_) || | | ||  \| |
|  _  || (_| || (__ |   <  | |_| ||  __/ | |_| || |\  |
|_| |_| \__,_| \___||_|\_\  \____||_|     \___/ |_| \_|
```

# omcilog2pcap (C#)
converts omci logs to pcap for easy view with wireshark ([omci plugin required](https://github.com/hack-gpon/omci-wireshark-dissector))

supported omci logs formats
- Lantiq-based chips (e.g. huawei ma5671a)
- Realtek-based chips (e.g. technicolor afm0002tim)
- Sagecomm devices
- Cortina Access devices (you can merge pkt_rx e pkt_tx into a single file and the software will re-order them automatically)
- Huawei S800e and B450

## Download
Prebuilt native executables for Windows (x64, arm64), Linux (x64, arm64) and macOS (x64, arm64) are available in the [releases](https://github.com/hack-gpon/omcilog2pcap/releases). No .NET installation required.

## Usage
```
omcilog2pcap <path of the omci log>
```
On Windows you can also drag&drop the omci log onto the executable (or into the console window).

The `.pcap` file is written in the current directory, with the same name as the log file.

## Build
Requires the [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0) and the [native AOT prerequisites](https://learn.microsoft.com/dotnet/core/deploying/native-aot/#prerequisites).
```
dotnet run --project src/omcilog2pcap -- <path of the omci log>
```
```
dotnet publish src/omcilog2pcap/omcilog2pcap.csproj -c Release -r <win-x64|win-arm64|linux-x64|linux-arm64|osx-x64|osx-arm64>
```

.NET 10.0 + native code generation (aot)

A JS version is also available in the [js branch](https://github.com/hack-gpon/omcilog2pcap/tree/js)

## Release
Releases are created automatically by CI on every push to `C#`: the version is read from `<Version>` in `src/omcilog2pcap/omcilog2pcap.csproj`, and if the `v<Version>` tag does not exist yet it is created together with the GitHub release. Bump `<Version>` to publish a new release.

## License
See [LICENSE](LICENSE).

More resources on [hack-gpon.org](https://hack-gpon.org/).
