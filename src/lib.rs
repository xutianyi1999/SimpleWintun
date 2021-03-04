use std::os::raw::c_void;

pub type Adapter = *mut c_void;
pub type Session = *mut c_void;
pub type Event = *mut c_void;
pub type Code = u8;

mod ffi {
    use std::os::raw::c_char;

    use crate::{Adapter, Code, Event, Session};

    extern {
        pub fn initialize_wintun() -> Code;

        pub fn create_adapter(
            pool_name: *const c_char,
            adapter_name: *const c_char,
            guid_str: *const c_char,
            adapter: *mut Adapter,
        ) -> Code;

        pub fn delete_adapter(adapter: Adapter) -> Code;

        pub fn delete_pool(pool_name: *const c_char) -> Code;

        pub fn get_adapter(
            pool_name: *const c_char,
            adapter_name: *const c_char,
            adapter: *mut Adapter,
        ) -> Code;

        pub fn get_adapter_name(
            adapter: Adapter,
            adapter_name: *mut c_char,
            size: u8,
        ) -> Code;

        pub fn set_adapter_name(adapter: Adapter, adapter_name: *const c_char) -> Code;

        pub fn set_ipaddr(
            adapter: Adapter,
            ipaddr: *const c_char,
            subnet_mask: u8,
        ) -> Code;

        pub fn open_adapter(
            adapter: Adapter,
            capacity: u32,
            session: *mut Session,
        ) -> Code;

        pub fn close_adapter(session: Session) -> ();

        pub fn get_read_wait_event(session: Session) -> Event;

        pub fn read_packet(
            session: Session,
            read_wait: Event,
            buff: *mut u8,
            size: *mut u32,
        ) -> Code;

        pub fn write_packet(
            session: Session,
            buff: *const u8,
            size: u32,
        ) -> Code;

        pub fn get_drive_version() -> u32;
    }
}

pub enum ReadResult {
    Success(usize),
    NotEnoughSize(usize),
}

pub mod raw {
    use std::io::{Error, ErrorKind, Result};
    use std::os::raw::c_char;
    use std::ptr::null_mut;
    use std::sync::Once;

    use crate::{Adapter, Code, Event, ffi, ReadResult, Session};

    const SUCCESS_CODE: Code = 0;
    //const OS_ERROR_CODE: Code = 1;
    const NOT_ENOUGH_SIZE_CODE: Code = 2;
    const PARSE_GUID_ERROR_CODE: Code = 3;
    //const IP_ADDRESS_ERROR_CODE: Code = 4;
    const STRING_COPY_ERROR_CODE: Code = 5;

    static INIT: Once = Once::new();

    pub fn initialize() {
        INIT.call_once(|| {
            let res = unsafe { ffi::initialize_wintun() };

            match res {
                SUCCESS_CODE => (),
                _ => panic!("Init error: {}", Error::last_os_error().to_string())
            };
        });
    }

    pub fn create_adapter(
        pool_name: &str,
        adapter_name: &str,
        guid: &str,
    ) -> Result<Adapter> {
        let mut adapter: Adapter = null_mut();

        let res = unsafe {
            ffi::create_adapter(
                (pool_name.to_owned() + "\0").as_ptr() as *const c_char,
                (adapter_name.to_owned() + "\0").as_ptr() as *const c_char,
                (guid.to_owned() + "\0").as_ptr() as *const c_char,
                &mut adapter,
            )
        };

        match res {
            SUCCESS_CODE => Ok(adapter),
            PARSE_GUID_ERROR_CODE => Err(Error::new(ErrorKind::Other, "Parse guid failed")),
            _ => Err(Error::last_os_error())
        }
    }

    pub fn delete_adapter(adapter: Adapter) -> Result<()> {
        let res = unsafe { ffi::delete_adapter(adapter) };

        match res {
            SUCCESS_CODE => Ok(()),
            _ => Err(Error::last_os_error())
        }
    }

    pub fn delete_pool(pool_name: &str) -> Result<()> {
        let res = unsafe { ffi::delete_pool((pool_name.to_owned() + "\0").as_ptr() as *const c_char) };

        match res {
            SUCCESS_CODE => Ok(()),
            _ => Err(Error::last_os_error())
        }
    }

    pub fn get_adapter(pool_name: &str, adapter_name: &str) -> Result<Adapter> {
        let mut adapter: Adapter = null_mut();

        let res = unsafe {
            ffi::get_adapter(
                (pool_name.to_owned() + "\0").as_ptr() as *const c_char,
                (adapter_name.to_owned() + "\0").as_ptr() as *const c_char,
                &mut adapter,
            )
        };

        match res {
            SUCCESS_CODE => Ok(adapter),
            _ => Err(Error::last_os_error())
        }
    }

    pub fn get_adapter_name(adapter: Adapter) -> Result<String> {
        let mut adapter_name = String::with_capacity(128);
        let res = unsafe { ffi::get_adapter_name(adapter, adapter_name.as_mut_ptr() as *mut c_char, 128) };

        match res {
            SUCCESS_CODE => Ok(adapter_name),
            STRING_COPY_ERROR_CODE => Err(Error::new(ErrorKind::Other, "String copy failed")),
            _ => Err(Error::last_os_error())
        }
    }

    pub fn set_ipaddr(adapter: Adapter, ipaddr: &str, subnet_mask: u8) -> Result<()> {
        let res = unsafe {
            ffi::set_ipaddr(
                adapter,
                (ipaddr.to_owned() + "\0").as_ptr() as *const c_char,
                subnet_mask,
            )
        };

        match res {
            SUCCESS_CODE => Ok(()),
            _ => Err(Error::new(ErrorKind::Other, "IP address error"))
        }
    }

    pub fn open_adapter(adapter: Adapter, capacity: u32) -> Result<Session> {
        let mut session: Session = null_mut();
        let res = unsafe { ffi::open_adapter(adapter, capacity, &mut session) };

        match res {
            SUCCESS_CODE => Ok(session),
            _ => Err(Error::last_os_error())
        }
    }

    #[inline]
    pub fn close_adapter(session: Session) -> () {
        unsafe { ffi::close_adapter(session) };
    }

    #[inline]
    pub fn get_read_wait_event(session: Session) -> Event {
        unsafe { ffi::get_read_wait_event(session) }
    }

    pub fn read_packet(
        session: Session,
        read_wait: Event,
        buff: &mut [u8],
    ) -> Result<ReadResult> {
        let mut size = buff.len() as u32;
        let res_code: Code = unsafe { ffi::read_packet(session, read_wait, buff.as_mut_ptr(), &mut size) };

        match res_code {
            SUCCESS_CODE => Ok(ReadResult::Success(size as usize)),
            NOT_ENOUGH_SIZE_CODE => Ok(ReadResult::NotEnoughSize(size as usize)),
            _ => Err(Error::last_os_error())
        }
    }

    pub fn write_packet(session: Session, buff: &[u8]) -> Result<()> {
        let res = unsafe { ffi::write_packet(session, buff.as_ptr(), buff.len() as u32) };

        match res {
            SUCCESS_CODE => Ok(()),
            _ => Err(Error::last_os_error())
        }
    }

    #[inline]
    pub fn get_drive_version() -> u32 {
        unsafe { ffi::get_drive_version() }
    }

    pub fn set_adapter_name(adapter: Adapter, adapter_name: &str) -> Result<()> {
        let res = unsafe { ffi::set_adapter_name(adapter, (adapter_name.to_owned() + "\0").as_ptr() as *const c_char) };

        match res {
            SUCCESS_CODE => Ok(()),
            _ => Err(Error::last_os_error())
        }
    }
}

pub mod adapter {
    use std::io::Result;

    use crate::{Adapter, Event, raw, ReadResult, Session};

    pub struct WintunAdapter {
        adapter: Adapter
    }

    impl WintunAdapter {
        pub fn initialize() -> () {
            raw::initialize()
        }

        pub fn create_adapter(
            pool_name: &str,
            adapter_name: &str,
            guid: &str,
        ) -> Result<WintunAdapter> {
            let adapter: Adapter = raw::create_adapter(pool_name, adapter_name, guid)?;
            Ok(WintunAdapter { adapter })
        }

        pub fn get_adapter(pool_name: &str, adapter_name: &str) -> Result<WintunAdapter> {
            let adapter: Adapter = raw::get_adapter(pool_name, adapter_name)?;
            Ok(WintunAdapter { adapter })
        }

        pub fn get_drive_version() -> u32 {
            raw::get_drive_version()
        }

        #[inline]
        pub fn delete_pool(pool_name: &str) -> Result<()> {
            raw::delete_pool(pool_name)
        }

        #[inline]
        pub fn delete_adapter(self) -> Result<()> {
            raw::delete_adapter(self.adapter)
        }

        #[inline]
        pub fn get_adapter_name(&self) -> Result<String> {
            raw::get_adapter_name(self.adapter)
        }

        #[inline]
        pub fn set_ipaddr(&self, ipaddr: &str, subnet_mask: u8) -> Result<()> {
            raw::set_ipaddr(self.adapter, ipaddr, subnet_mask)
        }

        pub fn open_adapter(&self, capacity: u32) -> Result<WintunStream> {
            let session: Session = raw::open_adapter(self.adapter, capacity)?;
            let event: Event = raw::get_read_wait_event(session);
            Ok(WintunStream { session, event })
        }

        #[inline]
        pub fn set_adapter_name(&self, adapter_name: &str) -> Result<()> {
            raw::set_adapter_name(self.adapter, adapter_name)
        }
    }

    pub struct WintunStream {
        session: Session,
        event: Event,
    }

    impl WintunStream {
        #[inline]
        pub fn close_adapter(self) {
            raw::close_adapter(self.session)
        }

        #[inline]
        pub fn read_packet(&self, buff: &mut [u8]) -> Result<ReadResult> {
            raw::read_packet(self.session, self.event, buff)
        }

        #[inline]
        pub fn write_packet(&self, buff: &[u8]) -> Result<()> {
            raw::write_packet(self.session, buff)
        }
    }

    impl Drop for WintunStream {
        #[inline]
        fn drop(&mut self) {
            raw::close_adapter(self.session)
        }
    }

    unsafe impl Send for WintunStream {}

    unsafe impl Sync for WintunStream {}
}

#[cfg(test)]
mod tests {
    use crate::adapter::WintunAdapter;

    #[test]
    fn get_derive_version() {
        let _ = WintunAdapter::get_drive_version();
    }

    #[test]
    fn create_delete_adapter() {
        let adapter = WintunAdapter::create_adapter("example", "test", "{D4C24D32-A723-DB80-A493-4E32E7883F15}").unwrap();
        adapter.delete_adapter().unwrap()
    }
}
