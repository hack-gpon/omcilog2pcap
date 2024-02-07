```
 _   _               _       ____  ____    ___   _   _ 
| | | |  __ _   ___ | | __  / ___||  _ \  / _ \ | \ | |
| |_| | / _` | / __|| |/ / | |  _ | |_) || | | ||  \| |
|  _  || (_| || (__ |   <  | |_| ||  __/ | |_| || |\  |
|_| |_| \__,_| \___||_|\_\  \____||_|     \___/ |_| \_|
```

# omcilog2pcap (ALPHA JS)
converts omci logs to pcap for easy view with wireshark ([omci plugin required](https://github.com/hack-gpon/omci-wireshark-dissector))

supported omci logs formats
- Lantiq-based chips (e.g. huawei ma5671a)
- Realtek-based chips (e.g. technicolor afm0002tim)
- Sagecomm devices
- Cortina Access devices (you can merge pkt_rx e pkt_tx into a single file and the software will re-order them automatically)

Converted to JS from [.NET 7.0 + native code generation (aot)](https://github.com/hack-gpon/omcilog2pcap/tree/C%23)
