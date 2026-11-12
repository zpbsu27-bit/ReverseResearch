The unchanged `evmole.wasm.gz` is from `github.com/cdump/evmole/go@v0.9.3`.
Source: https://github.com/cdump/evmole/tree/2b61bfcc64e2c027971d1547136b58b64db2e624/go
Tag: `refs/tags/go/v0.9.3`; module sum: `h1:0PcqE1JHzKMkef2B6avPhbo3v9E9yU/+YOt8/yjeLYU=`.
Compressed SHA-256: `dc1924ddf5f841bfb7b0b192ec2675f7cae76a8a67b19ee3c9d6ec00e191d4cb` (158883 bytes).
WASM SHA-256: `86b743afa235d84e90030ff2b33f2eb4628b72c42dba30c5be382700a7254983` (508338 bytes).
License: MIT, reproduced unchanged in `LICENSE.evmole`.

The RR host uses the official Go/Rust WASM ABI with selectors, arguments,
state mutability and terminal metadata enabled. It replaces only the Go host
configuration so resource limits and cancellation are enforced; it does not
reimplement EVMole's analysis. Other engine facets are not requested.

Only this analyzer is instantiated. The selected EVM carrier is data; no WASI,
host imports, filesystem, network, contract deployment or target execution are
provided. Each request owns and closes one runtime. The 256 MiB limit applies
to WASM linear memory; the surrounding Go process has additional memory use.
