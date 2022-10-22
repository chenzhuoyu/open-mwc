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

impl MACAddress {
    pub fn bytes(&self) -> [u8; 6] {
        self.buf
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

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
mod detail {
    use std::{
        alloc::Layout,
        io::{Error as IoError, Result as IoResult},
        ptr::null_mut,
    };

    use libc::{sockaddr_dl, sockaddr_in, sysctl, AF_INET, CTL_NET, NET_RT_FLAGS, PF_ROUTE};

    use super::MACAddress;

    #[cfg(target_os = "macos")]
    mod rtm {
        #[repr(C)]
        pub(super) struct rt_msghdr {
            pub rtm_msglen: libc::c_ushort,
            pub rtm_version: libc::c_uchar,
            pub rtm_type: libc::c_uchar,
            pub rtm_index: libc::c_ushort,
            pub rtm_flags: libc::c_int,
            pub rtm_addrs: libc::c_int,
            pub rtm_pid: libc::pid_t,
            pub rtm_seq: libc::c_int,
            pub rtm_errno: libc::c_int,
            pub rtm_use: libc::c_int,
            pub rtm_inits: u32,
            pub rtm_rmx: rt_metrics,
        }

        #[repr(C)]
        pub(super) struct rt_metrics {
            pub rmx_locks: u32,
            pub rmx_mtu: u32,
            pub rmx_hopcount: u32,
            pub rmx_expire: i32,
            pub rmx_recvpipe: u32,
            pub rmx_sendpipe: u32,
            pub rmx_ssthresh: u32,
            pub rmx_rtt: u32,
            pub rmx_rttvar: u32,
            pub rmx_pksent: u32,
            pub rmx_state: u32,
            pub rmx_filler: [u32; 3],
        }
    }

    #[cfg(target_os = "freebsd")]
    mod rtm {
        #[repr(C)]
        pub(super) struct rt_msghdr {
            pub rtm_msglen: libc::c_ushort,
            pub rtm_version: libc::c_uchar,
            pub rtm_type: libc::c_uchar,
            pub rtm_index: libc::c_ushort,
            pub rtm_flags: libc::c_int,
            pub rtm_addrs: libc::c_int,
            pub rtm_pid: libc::pid_t,
            pub rtm_seq: libc::c_int,
            pub rtm_errno: libc::c_int,
            pub rtm_use: libc::c_int,
            pub rtm_inits: libc::c_ulong,
            pub rtm_rmx: rt_metrics,
        }

        #[repr(C)]
        pub(super) struct rt_metrics {
            pub rmx_locks: libc::c_ulong,
            pub rmx_mtu: libc::c_ulong,
            pub rmx_hopcount: libc::c_ulong,
            pub rmx_expire: libc::c_ulong,
            pub rmx_recvpipe: libc::c_ulong,
            pub rmx_sendpipe: libc::c_ulong,
            pub rmx_ssthresh: libc::c_ulong,
            pub rmx_rtt: libc::c_ulong,
            pub rmx_rttvar: libc::c_ulong,
            pub rmx_pksent: libc::c_ulong,
            pub rmx_weight: libc::c_ulong,
            pub rmx_nhidx: libc::c_ulong,
            pub rmx_filler: [libc::c_ulong; 2],
        }
    }

    const RTM_SIZE: usize = std::mem::size_of::<rtm::rt_msghdr>();
    const RTF_LLINFO: i32 = 0x400;

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
            return Err(IoError::from_raw_os_error(ret));
        }

        /* empty table */
        if len == 0 {
            return Ok(None);
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
            let rtm = buf.byte_add(i) as *const rtm::rt_msghdr;
            let sin = rtm.byte_add(RTM_SIZE) as *const sockaddr_in;
            let sdl = sin.byte_add((&*sin).sin_len as usize) as *const sockaddr_dl;

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
    use std::io::{Error as IoError, Result as IoResult};

    use libc::{
        __errno_location, arpreq, close, freeifaddrs, getifaddrs, ifaddrs, ioctl, sockaddr_in,
        socket, strncpy, AF_INET, ATF_COM, ENXIO, IFF_POINTOPOINT, IFNAMSIZ, SIOCGARP, SOCK_DGRAM,
    };

    use super::MACAddress;

    pub(super) unsafe fn lookup_impl(addr: u32) -> IoResult<Option<MACAddress>> {
        let mut req = std::mem::zeroed::<arpreq>();
        let mut ifa = std::ptr::null_mut::<ifaddrs>();

        /* get all the interface addresses */
        if getifaddrs(&mut ifa as *mut *mut _) == -1 {
            return Err(IoError::from_raw_os_error(*__errno_location()));
        }

        /* create a new socket for querying ARP entries */
        let ifp = ifa;
        let sfd = socket(AF_INET, SOCK_DGRAM, 0);
        let sin = &mut *(&mut req.arp_pa as *mut _ as *mut sockaddr_in);

        /* check the socket */
        if sfd < 0 {
            return Err(IoError::from_raw_os_error(*__errno_location()));
        }

        /* iterate over the interface addresses */
        while !ifa.is_null() {
            let faddr = (*ifa).ifa_addr;
            let flags = (*ifa).ifa_flags;

            /* must have an address */
            if faddr.is_null() {
                ifa = (*ifa).ifa_next;
                continue;
            }

            /* must be an AF_INET address */
            if (*faddr).sa_family != AF_INET as u16 {
                ifa = (*ifa).ifa_next;
                continue;
            }

            /* ... which must not be a P2P address */
            if flags & IFF_POINTOPOINT as u32 != 0 {
                ifa = (*ifa).ifa_next;
                continue;
            }

            /* get the interface address and net mask */
            let iaddr = (*(faddr as *const sockaddr_in)).sin_addr.s_addr as u32;
            let nmask = (*((*ifa).ifa_netmask as *const sockaddr_in))
                .sin_addr
                .s_addr as u32;

            /* match the addresses */
            if addr & nmask != iaddr & nmask {
                ifa = (*ifa).ifa_next;
                continue;
            }

            /* fill the address */
            sin.sin_family = AF_INET as u16;
            sin.sin_addr.s_addr = addr;
            strncpy(&mut req.arp_dev as *mut _, (*ifa).ifa_name, IFNAMSIZ);

            /* lookup the ARP table */
            if ioctl(sfd, SIOCGARP, &mut req as *mut _) < 0 {
                if *__errno_location() == ENXIO {
                    ifa = (*ifa).ifa_next;
                    continue;
                } else {
                    close(sfd);
                    freeifaddrs(ifp as *mut _);
                    return Err(IoError::from_raw_os_error(*__errno_location()));
                }
            }

            /* check for completeness */
            if req.arp_flags & ATF_COM == 0 {
                ifa = (*ifa).ifa_next;
                continue;
            }

            /* close the socket */
            close(sfd);
            freeifaddrs(ifp as *mut _);

            /* build the MAC address */
            return Ok(Some(MACAddress::new([
                req.arp_ha.sa_data[0] as u8,
                req.arp_ha.sa_data[1] as u8,
                req.arp_ha.sa_data[2] as u8,
                req.arp_ha.sa_data[3] as u8,
                req.arp_ha.sa_data[4] as u8,
                req.arp_ha.sa_data[5] as u8,
            ])));
        }

        /* found nothing */
        close(sfd);
        freeifaddrs(ifp as *mut _);
        return Ok(None);
    }
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
        let ret = lookup(&Ipv4Addr::from_str(&"172.20.0.158")?)?;
        dbg!(ret);
        Ok(())
    }
}
