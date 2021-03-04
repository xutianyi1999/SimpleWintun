# SimpleWintun
Wintun rust API library

In Cargo.toml
```toml
[dependencies]
simple_wintun = "0.1"
```
Use
```rust
WintunAdapter::initialize();
let adapter = WintunAdapter::create_adapter("example", "test", "{D4C24D32-A723-DB80-A493-4E32E7883F15}").unwrap();
adapter.set_ipaddr("10.0.0.1", 24).unwrap();
let session = adapter.open_adapter(4096).unwrap();
```
