#[macro_use]
extern crate log;

use std::error::Error;
use std::fmt::{Debug, Display, Formatter};
use std::io;
use std::os::raw::c_void;

pub type AdapterHandle = *mut c_void;
pub type Session = *mut c_void;
pub type Event = *mut c_void;
pub type Code = u8;

#[derive(Copy, Clone)]
struct HandleWrap<H> {
    handle: H,
}

impl<H> HandleWrap<H> {
    fn new(handle: H) -> Self {
        HandleWrap { handle }
    }
}

unsafe impl<H> Send for HandleWrap<H> {}

unsafe impl<H> Sync for HandleWrap<H> {}

mod ffi {
    use std::os::raw::c_char;

    use crate::{AdapterHandle, Code, Event, Session};

    extern "C" {
        pub fn initialize_wintun() -> Code;

        pub fn delete_driver() -> Code;

        pub fn create_adapter(
            adapter_name: *const c_char,
            tunnel_type: *const c_char,
            guid_str: *const c_char,
            adapter: *mut AdapterHandle,
        ) -> Code;

        pub fn open_adapter(
            adapter_name: *const c_char,
            adapter: *mut AdapterHandle,
        ) -> Code;

        pub fn close_adapter(adapter: AdapterHandle);

        pub fn get_driver_version(version: *mut u32) -> Code;

        pub fn start_session(
            adapter: AdapterHandle,
            capacity: u32,
            session: *mut Session,
        ) -> Code;

        pub fn end_session(session: Session);

        pub fn get_read_wait_event(session: Session) -> Event;

        pub fn wait_event(event: Event, time: u32) -> Code;

        pub fn read_packet_nonblock(
            session: Session,
            buff: *mut u8,
            size: *mut u32,
        ) -> Code;

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

        pub fn set_ipaddr(
            adapter: AdapterHandle,
            ipaddr: *const c_char,
            subnet_mask: u8,
        ) -> Code;
    }
}

#[derive(Debug)]
pub enum WaitError {
    Timeout,
    IoError(io::Error),
}

impl Display for WaitError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            WaitError::Timeout => write!(f, "Wait timeout"),
            WaitError::IoError(e) => write!(f, "{}", e)
        }
    }
}

impl Error for WaitError {}

#[derive(Debug)]
pub enum ReadError {
    NotEnoughSize(usize),
    IoError(io::Error),
    NoMoreItems,
}

impl Display for ReadError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ReadError::IoError(e) => write!(f, "{}", e),
            ReadError::NotEnoughSize(len) => write!(f, "Not enough size: {}", len),
            ReadError::NoMoreItems => write!(f, "No more items")
        }
    }
}

impl Error for ReadError {}

impl From<ReadError> for io::Error {
    fn from(e: ReadError) -> Self {
        match e {
            ReadError::NotEnoughSize(_) => io::Error::new(io::ErrorKind::Other, e),
            ReadError::IoError(e) => e,
            ReadError::NoMoreItems => io::Error::new(io::ErrorKind::WouldBlock, "No more items")
        }
    }
}

pub mod raw {
    use std::io::{Error, ErrorKind, Result};
    use std::os::raw::c_char;
    use std::ptr::null_mut;

    use crate::{AdapterHandle, Code, Event, ffi, ReadError, Session, WaitError};

    const SUCCESS_CODE: Code = 0;
    #[allow(dead_code)]
    const OS_ERROR_CODE: Code = 1;
    const NOT_ENOUGH_SIZE_CODE: Code = 2;
    const PARSE_GUID_ERROR_CODE: Code = 3;
    #[allow(dead_code)]
    const IP_ADDRESS_ERROR_CODE: Code = 4;
    const EVENT_WAIT_TIMEOUT: Code = 5;

    pub fn initialize() -> Result<()> {
        let res = unsafe { ffi::initialize_wintun() };

        match res {
            SUCCESS_CODE => Ok(()),
            _ => Err(Error::last_os_error())
        }
    }

    pub fn delete_driver() -> Result<()> {
        let res = unsafe { ffi::delete_driver() };

        match res {
            SUCCESS_CODE => Ok(()),
            _ => Err(Error::last_os_error())
        }
    }

    pub fn create_adapter(
        adapter_name: &str,
        tunnel_type: &str,
        guid: &str,
    ) -> Result<AdapterHandle> {
        let mut adapter: AdapterHandle = null_mut();

        let res = unsafe {
            ffi::create_adapter(
                (adapter_name.to_owned() + "\0").as_ptr() as *const c_char,
                (tunnel_type.to_owned() + "\0").as_ptr() as *const c_char,
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

    pub fn open_adapter(adapter_name: &str) -> Result<AdapterHandle> {
        let mut adapter: AdapterHandle = null_mut();

        let res = unsafe {
            ffi::open_adapter(
                (adapter_name.to_owned() + "\0").as_ptr() as *const c_char,
                &mut adapter,
            )
        };

        match res {
            SUCCESS_CODE => Ok(adapter),
            _ => Err(Error::last_os_error())
        }
    }

    pub fn close_adapter(adapter: AdapterHandle) {
        unsafe { ffi::close_adapter(adapter) }
    }

    pub fn get_driver_version() -> Result<u32> {
        let mut version = 0;
        let res = unsafe { ffi::get_driver_version(&mut version) };

        match res {
            SUCCESS_CODE => Ok(version),
            _ => Err(Error::last_os_error())
        }
    }

    pub fn start_session(adapter: AdapterHandle, capacity: u32) -> Result<Session> {
        let mut session: Session = null_mut();
        let res = unsafe { ffi::start_session(adapter, capacity, &mut session) };

        match res {
            SUCCESS_CODE => Ok(session),
            _ => Err(Error::last_os_error())
        }
    }

    pub fn end_session(session: Session) -> () {
        unsafe { ffi::end_session(session) };
    }

    pub fn get_read_wait_event(session: Session) -> Event {
        unsafe { ffi::get_read_wait_event(session) }
    }

    pub fn wait_event(event: Event, time_ms: u32) -> std::result::Result<(), WaitError> {
        let res = unsafe { ffi::wait_event(event, time_ms) };

        match res {
            SUCCESS_CODE => Ok(()),
            EVENT_WAIT_TIMEOUT => Err(WaitError::Timeout),
            _ => Err(WaitError::IoError(Error::last_os_error()))
        }
    }

    pub fn read_packet_nonblock(session: Session, buff: &mut [u8]) -> std::result::Result<usize, ReadError> {
        let mut size = buff.len() as u32;
        let res_code: Code = unsafe { ffi::read_packet_nonblock(session, buff.as_mut_ptr(), &mut size) };

        match res_code {
            SUCCESS_CODE => Ok(size as usize),
            NOT_ENOUGH_SIZE_CODE => Err(ReadError::NotEnoughSize(size as usize)),
            _ => {
                const ERROR_NO_MORE_ITEMS: i32 = 259;
                let err = Error::last_os_error();

                if err.raw_os_error() == Some(ERROR_NO_MORE_ITEMS) {
                    Err(ReadError::NoMoreItems)
                } else {
                    Err(ReadError::IoError(err))
                }
            }
        }
    }

    pub fn read_packet(
        session: Session,
        read_wait: Event,
        buff: &mut [u8],
    ) -> std::result::Result<usize, ReadError> {
        let mut size = buff.len() as u32;
        let res_code: Code = unsafe { ffi::read_packet(session, read_wait, buff.as_mut_ptr(), &mut size) };

        match res_code {
            SUCCESS_CODE => Ok(size as usize),
            NOT_ENOUGH_SIZE_CODE => Err(ReadError::NotEnoughSize(size as usize)),
            _ => Err(ReadError::IoError(Error::last_os_error()))
        }
    }

    pub fn write_packet(session: Session, buff: &[u8]) -> Result<()> {
        let res = unsafe { ffi::write_packet(session, buff.as_ptr(), buff.len() as u32) };

        match res {
            SUCCESS_CODE => Ok(()),
            _ => Err(Error::last_os_error())
        }
    }

    pub fn set_ipaddr(adapter: AdapterHandle, ipaddr: &str, subnet_mask: u8) -> Result<()> {
        let res = unsafe {
            ffi::set_ipaddr(
                adapter,
                (ipaddr.to_owned() + "\0").as_ptr() as *const c_char,
                subnet_mask,
            )
        };

        match res {
            SUCCESS_CODE => Ok(()),
            _ => Err(Error::new(ErrorKind::Other, "Set ip address failed"))
        }
    }
}

pub mod adapter {
    use std::io::{Error, ErrorKind, Result};
    use std::sync::Mutex;

    use once_cell::sync::Lazy;

    use crate::{AdapterHandle, Event, HandleWrap, raw, ReadError, Session};

    fn initialize() -> Result<()> {
        static STATE: Lazy<Mutex<bool>> = Lazy::new(|| Mutex::new(false));
        let mut guard = STATE.lock().map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;

        if !*guard {
            raw::initialize()?;
            *guard = true;
            Ok(())
        } else {
            Ok(())
        }
    }

    pub struct WintunAdapter {
        adapter: HandleWrap<AdapterHandle>,
        adapter_name: String,
    }

    impl Drop for WintunAdapter {
        fn drop(&mut self) {
            raw::close_adapter(self.adapter.handle);

            if let Err(e) = raw::delete_driver() {
                error!("Delete wintun driver error: {}", e);
            }
        }
    }

    impl WintunAdapter {
        pub fn create_adapter(
            adapter_name: &str,
            tunnel_type: &str,
            guid: &str,
        ) -> Result<WintunAdapter> {
            initialize()?;
            let adapter: AdapterHandle = raw::create_adapter(adapter_name, tunnel_type, guid)?;

            Ok(WintunAdapter {
                adapter: HandleWrap::new(adapter),
                adapter_name: tunnel_type.to_string(),
            })
        }

        pub fn open_adapter(adapter_name: &str) -> Result<WintunAdapter> {
            initialize()?;
            let adapter: AdapterHandle = raw::open_adapter(adapter_name)?;

            Ok(WintunAdapter {
                adapter: HandleWrap::new(adapter),
                adapter_name: adapter_name.to_string(),
            })
        }

        pub fn get_driver_version(&self) -> Result<u32> {
            raw::get_driver_version()
        }

        pub fn close(self) {}

        pub fn get_adapter_name(&self) -> &str {
            &self.adapter_name
        }

        #[inline]
        pub fn set_ipaddr(&self, ipaddr: &str, subnet_mask: u8) -> Result<()> {
            raw::set_ipaddr(self.adapter.handle, ipaddr, subnet_mask)
        }

        pub fn start_session(&self, capacity: u32) -> Result<WintunStream> {
            let session: Session = raw::start_session(self.adapter.handle, capacity)?;
            let event: Event = raw::get_read_wait_event(session);

            Ok(WintunStream {
                _adapter: self,
                session: HandleWrap::new(session),
                event: HandleWrap::new(event),
            })
        }
    }

    pub struct WintunStream<'a> {
        _adapter: &'a WintunAdapter,
        session: HandleWrap<Session>,
        event: HandleWrap<Event>,
    }

    impl WintunStream<'_> {
        pub fn read_packet(&self, buff: &mut [u8]) -> std::result::Result<usize, ReadError> {
            raw::read_packet(
                self.session.handle,
                self.event.handle,
                buff,
            )
        }

        pub fn write_packet(&self, buff: &[u8]) -> Result<()> {
            raw::write_packet(self.session.handle, buff)
        }
    }

    impl Drop for WintunStream<'_> {
        fn drop(&mut self) {
            raw::end_session(self.session.handle)
        }
    }

    #[cfg(feature = "async")]
    mod async_mod {
        use std::io;

        use crate::{raw, ReadError, WaitError};
        use crate::adapter::WintunStream;

        impl WintunStream<'_> {
            pub async fn async_read_packet(&self, buff: &mut [u8]) -> Result<usize, ReadError> {
                loop {
                    let res = raw::read_packet_nonblock(self.session.handle, buff);

                    match res {
                        Err(ReadError::NoMoreItems) => {
                            let event = self.event;

                            match blocking::unblock(move || {
                                let e = event;
                                raw::wait_event(e.handle, u32::MAX)
                            }).await {
                                Ok(_) => {}
                                Err(WaitError::IoError(e)) => return Err(ReadError::IoError(e)),
                                Err(WaitError::Timeout) => return Err(ReadError::IoError(io::Error::new(io::ErrorKind::Other, "Wait event timeout")))
                            };
                        }
                        _ => return res
                    }
                }
            }
        }
    }
}