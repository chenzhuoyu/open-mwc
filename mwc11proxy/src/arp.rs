use std::{
    fmt::{Debug, Display, Formatter, Result as FmtResult},
    io::{Error as IoError, ErrorKind},
    net::Ipv4Addr,
};

use crate::{as_err, Maybe};

#[derive(Copy, Clone, Hash, PartialEq, Eq)]
pub struct MACAddress {
    buf: [u8; 6],
}

impl MACAddress {
    fn new(buf: [u8; 6]) -> Self {
        Self { buf }
    }
}

impl Debug for MACAddress {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("MACAddress")
            .field("buf", &self.to_string())
            .finish()
    }
}

impl Display for MACAddress {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.buf[0], self.buf[1], self.buf[2], self.buf[3], self.buf[4], self.buf[5]
        )
    }
}

#[cfg(target_os = "macos")]
mod detail {
    use std::{
        alloc::Layout,
        io::{Error as IoError, Result as IoResult},
        ptr::null_mut,
    };

    use libc::{
        __error, sockaddr_dl, sockaddr_inarp, sysctl, AF_INET, CTL_NET, NET_RT_FLAGS, PF_ROUTE,
        RTF_LLINFO,
    };

    use super::MACAddress;

    #[repr(C)]
    #[derive(Debug, Clone, Copy, Default)]
    struct rt_msghdr {
        pub rtm_msglen: libc::c_ushort, // to skip over non-understood messages
        pub rtm_version: libc::c_uchar, // future binary compatibility
        pub rtm_type: libc::c_uchar,    // message type
        pub rtm_index: libc::c_ushort,  // index for associated ifp
        pub rtm_flags: libc::c_int,     // flags, incl. kern & message, e.g. DONE
        pub rtm_addrs: libc::c_int,     // bitmask identifying sockaddrs in msg
        pub rtm_pid: libc::pid_t,       // identify sender
        pub rtm_seq: libc::c_int,       // for sender to identify action
        pub rtm_errno: libc::c_int,     // why failed
        pub rtm_use: libc::c_int,       // from rtentry
        pub rtm_inits: u32,             // which metrics we are initializing
        pub rtm_rmx: rt_metrics,        // metrics themselves
    }

    #[repr(C)]
    #[derive(Debug, Clone, Copy, Default)]
    struct rt_metrics {
        pub rmx_locks: u32,       // Kernel leaves these values alone
        pub rmx_mtu: u32,         // MTU for this path
        pub rmx_hopcount: u32,    // max hops expected
        pub rmx_expire: i32,      // lifetime for route, e.g. redirect
        pub rmx_recvpipe: u32,    // inbound delay-bandwidth product
        pub rmx_sendpipe: u32,    // outbound delay-bandwidth product
        pub rmx_ssthresh: u32,    // outbound gateway buffer limit
        pub rmx_rtt: u32,         // estimated round trip time
        pub rmx_rttvar: u32,      // estimated rtt variance
        pub rmx_pksent: u32,      // packets sent using this route
        pub rmx_state: u32,       // route state
        pub rmx_filler: [u32; 3], // will be used for T/TCP later
    }

    pub(super) unsafe fn lookup_impl(addr: u32) -> IoResult<Option<MACAddress>> {
        let mut len = 0;
        let mut mib = [CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_FLAGS, RTF_LLINFO];

        /* calculate the needed length */
        let ret = sysctl(
            &mut mib as *mut _,
            6,
            null_mut(),
            &mut len as *mut _,
            null_mut(),
            0,
        );

        /* check for errors */
        if ret < 0 {
            return Err(IoError::from_raw_os_error(*__error()));
        }

        /* allocate raw memory */
        let ly = Layout::array::<u8>(len).unwrap();
        let buf = std::alloc::alloc(ly);

        /* check for allocation */
        if buf.is_null() {
            panic!("cannot allocate memory for ARP entries");
        }

        /* actually retrieve the data */
        let ret = sysctl(
            &mut mib as *mut _,
            6,
            buf as *mut _,
            &mut len as *mut _,
            null_mut(),
            0,
        );

        /* check for errors */
        if ret < 0 {
            return Err(IoError::from_raw_os_error(ret));
        }

        /* result buffer */
        let mut i = 0;
        let mut ret = None;

        /* find the address in question */
        while i < len {
            let rtm = buf.add(i) as *const rt_msghdr;
            let sin = rtm.add(1) as *const sockaddr_inarp;
            let sdl = sin.add(1) as *const sockaddr_dl;

            /* check if the address is complete and matches the requested address */
            if (&*sdl).sdl_alen == 0 || (&*sin).sin_addr.s_addr != addr {
                i += (&*rtm).rtm_msglen as usize;
                continue;
            }

            /* copy the MAC address */
            let mac = MACAddress::new([
                (&*sdl).sdl_data[(&*sdl).sdl_nlen as usize] as u8,
                (&*sdl).sdl_data[(&*sdl).sdl_nlen as usize + 1] as u8,
                (&*sdl).sdl_data[(&*sdl).sdl_nlen as usize + 2] as u8,
                (&*sdl).sdl_data[(&*sdl).sdl_nlen as usize + 3] as u8,
                (&*sdl).sdl_data[(&*sdl).sdl_nlen as usize + 4] as u8,
                (&*sdl).sdl_data[(&*sdl).sdl_nlen as usize + 5] as u8,
            ]);

            /* store the address */
            ret = Some(mac);
            break;
        }

        /* free the memory space */
        std::alloc::dealloc(buf, ly);
        Ok(ret)
    }
}

#[cfg(target_os = "linux")]
mod detail {
    pub(super) unsafe fn lookup_impl(addr: u32) -> IoResult<Option<MACAddress>> {}
}

pub fn lookup(addr: &Ipv4Addr) -> Maybe<MACAddress> {
    match unsafe { detail::lookup_impl(u32::from_le_bytes(addr.octets()))? } {
        Some(v) => Ok(v),
        None => Err(as_err(IoError::from(ErrorKind::AddrNotAvailable))),
    }
}

#[cfg(test)]
mod test {
    use std::{net::Ipv4Addr, str::FromStr};

    use super::lookup;
    use crate::Unit;

    #[test]
    fn test_resolve() -> Unit {
        let ret = lookup(&Ipv4Addr::from_str(&"172.20.0.135")?)?;
        dbg!(ret);
        Ok(())
    }
}
