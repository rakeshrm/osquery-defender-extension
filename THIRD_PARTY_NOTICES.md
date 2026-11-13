# Third-party notices

## Protokol-7 — mpenginedb_parser and MpEngineDb_SQLECmd

The MetaVault format research, the built-in RC4 key for Defender engine
1.1.26100.4, the keystream-derivation approach (ported in
`defender/internal/mpengine/codec.go`) and the ASR rule GUID→name list
(`defender/internal/tables/asr.go`) come from:

- https://github.com/Protokol-7/mpenginedb_parser
- https://github.com/Protokol-7/MpEngineDb_SQLECmd
- https://protokol-7.github.io/dfir/2026/11/10/defenders-hidden-flight-recorder-mpenginedb.html

```
MIT License

Copyright (c) 2026 Protokol-7

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Go dependencies

Binaries statically link `github.com/osquery/osquery-go` (MIT),
`modernc.org/sqlite` (BSD-3-Clause) and their dependencies; see
`defender/go.mod` for the full list and each module for its license.
