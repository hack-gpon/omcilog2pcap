# omcilog2pcap
converts omci logs to pcap for easy view with wireshark (omci plugin required)

supported omci logs formats
- lantiq-based chips (e.g. huawei ma5671a)
- realtek-based chips (e.g. technicolor afm0002tim)
- Sgecomm devices
- Cortina Access devices (you can merge pkt_rx e pkt_tx into a single file and the software will re-order them automatically)


Quickly made in 1 hour, it may have bugs or quirks ¯\\\_(ツ)_/¯


.NET 7.0 + native code generation (aot)