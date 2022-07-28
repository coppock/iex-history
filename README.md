# IEX History

This repository contains a program to convert [IEX historical data](
https://iextrading.com/trading/market-data/#hist-download) from packet captures
to CSVs.

Each record of output corresponds to an IEX-TP message. Note: different
message types will result in records with different numbers of fields.
Currently, only **system event** and **trade report** messages are parsed. This
is enough to construct OHLC bars with volume during trading hours.

Messages are comprised of typed fields. Except **byte**s and **timestamp**s,
types are intuitively formatted. **byte**s are formatted either as ASCII
characters or as hex digits depending on whether the ASCII representation has
meaning. **timestamp**s are formatted in accordance with RFC 3339.

See the [IEX TOPS specification](
https://storage.googleapis.com/assets-bucket/exchange/assets/IEX%20TOPS%20Specification%20v1.66.pdf
) for details.

## Build Instructions

```
make pcap2csv
```

The build has been tested on macOS using the BSD development commands.
