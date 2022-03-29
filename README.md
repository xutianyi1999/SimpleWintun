# SimpleWintun

Wintun rust API library

### Usage

Wintun.dll (https://www.wintun.net) needs to be in the same directory as the executable file or under System32

Cargo.toml

```toml
[dependencies]
simple_wintun = { git = "https://github.com/xutianyi1999/SimpleWintun.git" }
```

```rust
use std::net::Ipv4Addr;
use std::ops::Range;
use simple_wintun::adapter::WintunAdapter;
use simple_wintun::ReadResult;

const SRC_ADDR: Range<usize> = 12..16;
const DST_ADDR: Range<usize> = 16..20;

fn main() {
    let adapter = WintunAdapter::create_adapter("example", "test", "{D4C24D32-A723-DB80-A493-4E32E7883F15}").unwrap();
    adapter.set_ipaddr("192.168.8.1", 24).unwrap();
    let session = adapter.start_session(4096).unwrap();

    let mut buff = vec![0u8; 65536];

    loop {
        let packet = match session.read_packet(&mut buff) {
            Ok(ReadResult::Success(len)) => &buff[..len],
            Ok(ReadResult::NotEnoughSize(_)) => continue,
            Err(e) => {
                eprintln!("error: {}", e);
                return
            }
        };

        let mut buff = [0u8; 4];

        buff.copy_from_slice(&packet[SRC_ADDR]);
        let src_addr = Ipv4Addr::from(buff);

        buff.copy_from_slice(&packet[DST_ADDR]);
        let dst_addr = Ipv4Addr::from(buff);

        println!("packet {} -> {}", src_addr, dst_addr)
    }
}
```
