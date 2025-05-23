use std::alloc::{alloc_zeroed, dealloc, Layout};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use std::ptr::null;

use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_SUCCESS};
use windows_sys::Win32::Globalization::{CP_ACP, MB_ERR_INVALID_CHARS, MB_PRECOMPOSED, MultiByteToWideChar};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetAdaptersAddresses, GAA_FLAG_INCLUDE_ALL_COMPARTMENTS, GAA_FLAG_INCLUDE_ALL_INTERFACES,
    GAA_FLAG_INCLUDE_GATEWAYS, GAA_FLAG_INCLUDE_PREFIX, GAA_FLAG_INCLUDE_TUNNEL_BINDINGORDER,
    GAA_FLAG_INCLUDE_WINS_INFO, IP_ADAPTER_ADDRESSES_LH,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6};


#[derive(Debug, Eq, Hash, PartialEq)]
struct FreeOnDrop<T> {
    pub layout: Layout,
    pub buffer: *mut T,
}
impl<T> FreeOnDrop<T> {
    pub fn new(layout: Layout) -> Self {
        if layout.size() < std::mem::size_of::<T>() {
            panic!("too small! layout wants {} but size_of::<T> is {}", layout.size(), std::mem::size_of::<T>());
        }
        let buffer = unsafe { alloc_zeroed(layout) } as *mut T;
        Self {
            layout,
            buffer,
        }
    }
}
impl<T> Drop for FreeOnDrop<T> {
    fn drop(&mut self) {
        unsafe { dealloc(self.buffer as *mut u8, self.layout) };
    }
}


fn pstr_to_string(pstr: windows_sys::core::PSTR) -> Option<String> {
    if pstr.is_null() {
        return None;
    }

    // convert to UTF-16
    let buf_required_chars_i32 = unsafe {
        MultiByteToWideChar(
            CP_ACP,
            MB_PRECOMPOSED | MB_ERR_INVALID_CHARS,
            pstr,
            -1,
            std::ptr::null_mut(),
            0,
        )
    };
    if buf_required_chars_i32 < 1 {
        panic!("MultiByteToWideChar tells me it wants a buffer of {} bytes", buf_required_chars_i32);
    }
    let buf_required_chars: usize = buf_required_chars_i32.try_into().unwrap();
    let mut utf16_buf = vec![0u16; buf_required_chars];
    let copied_chars_i32 = unsafe {
        MultiByteToWideChar(
            CP_ACP,
            MB_PRECOMPOSED | MB_ERR_INVALID_CHARS,
            pstr,
            -1,
            utf16_buf.as_mut_ptr(),
            buf_required_chars_i32,
        )
    };
    if copied_chars_i32 < 1 {
        panic!("MultiByteToWideChar tells me it copied {} bytes", copied_chars_i32);
    }

    Some(
        String::from_utf16(&utf16_buf)
            .expect("MultiByteToWideChar returned invalid UTF-16 data")
    )
}

fn pwstr_to_string(pwstr: windows_sys::core::PWSTR) -> Option<String> {
    if pwstr.is_null() {
        return None;
    }

    let mut walker = pwstr;
    let mut length = 0;
    while unsafe { *walker } != 0x0000 {
        length += 1;
        walker = walker.wrapping_add(1);
    }
    let utf16_slice = unsafe { std::slice::from_raw_parts(pwstr, length) };
    Some(
        String::from_utf16(&utf16_slice)
            .expect("invalid UTF-16 data")
    )
}

fn sockaddr_to_string(sockaddr: *const SOCKADDR) -> Option<String> {
    if sockaddr.is_null() {
        return None;
    }

    let family = unsafe { *sockaddr }.sa_family;
    match family {
        AF_INET => {
            let sockaddr_ipv4 = unsafe { &*(sockaddr as *const SOCKADDR_IN) };
            let port = u16::from_be(sockaddr_ipv4.sin_port);
            let ipv4_bits = u32::from_be(unsafe { sockaddr_ipv4.sin_addr.S_un.S_addr });
            Some(SocketAddrV4::new(Ipv4Addr::from_bits(ipv4_bits), port).to_string())
        },
        AF_INET6 => {
            let sockaddr_ipv6 = unsafe { &*(sockaddr as *const SOCKADDR_IN6) };
            let port = u16::from_be(sockaddr_ipv6.sin6_port);
            let mut addr_words = unsafe { sockaddr_ipv6.sin6_addr.u.Word };
            for word in addr_words.iter_mut() {
                *word = u16::from_be(*word);
            }
            let scope_id = u32::from_be(unsafe { sockaddr_ipv6.Anonymous.sin6_scope_id });
            Some(SocketAddrV6::new(Ipv6Addr::from(addr_words), port, sockaddr_ipv6.sin6_flowinfo, scope_id).to_string())
        },
        other => {
            let data = unsafe { *sockaddr }.sa_data;
            Some(format!("unknown address family {:#06X} address {:?}", other, data))
        },
    }
}

fn guid_to_string(guid: &GUID) -> String {
    format!(
        "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        guid.data1,
        guid.data2,
        guid.data3,
        guid.data4[0],
        guid.data4[1],
        guid.data4[2],
        guid.data4[3],
        guid.data4[4],
        guid.data4[5],
        guid.data4[6],
        guid.data4[7],
    )
}


macro_rules! output_addresses {
    (@has_flags, $addr:expr, $addr_type:expr, $addr_field:ident) => {
        {
            println!("{} addresses:", $addr_type);
            let mut ac_addr = unsafe { (*$addr).$addr_field };
            while !ac_addr.is_null() {
                println!("  Address");
                println!("    Flags: {}", unsafe { (*ac_addr).Anonymous.Anonymous }.Flags);
                println!("    Length: {}", unsafe { (*ac_addr).Anonymous.Anonymous }.Length);
                println!("    AddrLength: {}", unsafe { *ac_addr }.Address.iSockaddrLength);
                println!("    Address: {:?}", sockaddr_to_string(unsafe { (*ac_addr).Address.lpSockaddr }));

                ac_addr = unsafe { *ac_addr }.Next;
            }
        }
    };
    (@no_flags, $addr:expr, $addr_type:expr, $addr_field:ident) => {
        {
            println!("{} addresses:", $addr_type);
            let mut ac_addr = unsafe { (*$addr).$addr_field };
            while !ac_addr.is_null() {
                println!("  Address");
                println!("    Length: {}", unsafe { (*ac_addr).Anonymous.Anonymous }.Length);
                println!("    AddrLength: {}", unsafe { *ac_addr }.Address.iSockaddrLength);
                println!("    Address: {:?}", sockaddr_to_string(unsafe { (*ac_addr).Address.lpSockaddr }));

                ac_addr = unsafe { *ac_addr }.Next;
            }
        }
    };
}


fn main() {
    const GAA_FLAGS: u32 =
        GAA_FLAG_INCLUDE_PREFIX
        | GAA_FLAG_INCLUDE_WINS_INFO
        | GAA_FLAG_INCLUDE_GATEWAYS
        | GAA_FLAG_INCLUDE_ALL_INTERFACES
        | GAA_FLAG_INCLUDE_ALL_COMPARTMENTS
        | GAA_FLAG_INCLUDE_TUNNEL_BINDINGORDER
    ;
    const STRUCT_SIZE: usize = std::mem::size_of::<IP_ADAPTER_ADDRESSES_LH>();
    const STRUCT_ALIGNMENT: usize = std::mem::align_of::<IP_ADAPTER_ADDRESSES_LH>();
    let initial_layout = Layout::from_size_align(STRUCT_SIZE, STRUCT_ALIGNMENT)
        .expect("failed to construct initial layout");

    let initial_buf = FreeOnDrop::new(initial_layout);

    let mut buf_size: u32 = STRUCT_SIZE.try_into().unwrap();
    let ret = unsafe {
        GetAdaptersAddresses(
            AF_UNSPEC.into(),
            GAA_FLAGS,
            null(),
            initial_buf.buffer,
            &mut buf_size,
        )
    };
    let buffer = if ret == ERROR_BUFFER_OVERFLOW {
        // buffer not big enough
        drop(initial_buf);
        let new_size: usize = buf_size.try_into()
            .expect("failed to convert wanted byte count to usize");
        let new_layout = Layout::from_size_align(new_size, STRUCT_ALIGNMENT)
            .expect("failed to construct new layout");
        let new_buf = FreeOnDrop::new(new_layout);
        let ret = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC.into(),
                GAA_FLAGS,
                null(),
                new_buf.buffer,
                &mut buf_size,
            )
        };
        if ret != ERROR_SUCCESS {
            drop(new_buf);
            panic!("GetAdaptersAddresses error: {}", ret);
        }
        new_buf
    } else if ret != ERROR_SUCCESS {
        drop(initial_buf);
        panic!("GetAdaptersAddresses error: {}", ret);
    } else {
        initial_buf
    };

    let mut addr = buffer.buffer;
    while !addr.is_null() {
        println!("IfIndex: {}", unsafe { (*addr).Anonymous1.Anonymous }.IfIndex);
        println!("Length: {}", unsafe { (*addr).Anonymous1.Anonymous }.Length);
        println!("AdapterName: {:?}", pstr_to_string(unsafe { *addr }.AdapterName));

        output_addresses!(@has_flags, addr, "Unicast", FirstUnicastAddress);
        output_addresses!(@has_flags, addr, "Anycast", FirstAnycastAddress);
        output_addresses!(@has_flags, addr, "Multicast", FirstMulticastAddress);

        println!("DNS suffix: {:?}", pwstr_to_string(unsafe { *addr }.DnsSuffix));
        println!("Description: {:?}", pwstr_to_string(unsafe { *addr }.Description));
        println!("Friendly name: {:?}", pwstr_to_string(unsafe { *addr }.FriendlyName));

        print!("Physical address:");
        let addr_len: usize = usize::try_from(unsafe { *addr }.PhysicalAddressLength).unwrap()
            .min(unsafe { *addr }.PhysicalAddress.len());
        for b in &unsafe { *addr }.PhysicalAddress[..addr_len] {
            print!(" {:02X}", b);
        }
        println!();

        println!("Flags: {}", unsafe { (*addr).Anonymous2.Flags });
        println!("MTU: {}", unsafe { *addr }.Mtu);
        println!("IfType: {}", unsafe { *addr }.IfType);
        println!("OperStatus: {}", unsafe { *addr }.OperStatus);
        println!("Ipv6IfIndex: {}", unsafe { *addr }.Ipv6IfIndex);
        for (i, zone_index) in unsafe { *addr }.ZoneIndices.iter().enumerate() {
            println!("Zone index {}: {}", i, zone_index);
        }

        println!("Prefixes:");
        let mut pfx = unsafe { (*addr).FirstPrefix };
        while !pfx.is_null() {
            println!("  Prefix");
            println!("    Flags: {}", unsafe { (*pfx).Anonymous.Anonymous }.Flags);
            println!("    Structure Length: {}", unsafe { (*pfx).Anonymous.Anonymous }.Length);
            println!("    AddrLength: {}", unsafe { *pfx }.Address.iSockaddrLength);
            println!("    Address: {:?}", sockaddr_to_string(unsafe { (*pfx).Address.lpSockaddr }));
            println!("    Prefix Length: {}", unsafe { *pfx }.PrefixLength);

            pfx = unsafe { *pfx }.Next;
        }

        println!("Transmit speed: {}", unsafe { *addr }.TransmitLinkSpeed);
        println!("Receive speed: {}", unsafe { *addr }.ReceiveLinkSpeed);

        output_addresses!(@no_flags, addr, "WINS server", FirstWinsServerAddress);
        output_addresses!(@no_flags, addr, "Gateway", FirstGatewayAddress);

        println!("IPv4 Metric: {}", unsafe { *addr }.Ipv4Metric);
        println!("IPv6 Metric: {}", unsafe { *addr }.Ipv6Metric);
        println!("LUID: {}", unsafe { (*addr).Luid.Value });
        println!("DHCPv4 server: {:?}", sockaddr_to_string(unsafe { *addr }.Dhcpv4Server.lpSockaddr));
        println!("Compartment ID: {}", unsafe { *addr }.CompartmentId);
        println!("Network GUID: {}", guid_to_string(&unsafe { *addr }.NetworkGuid));
        println!("Connection type: {}", unsafe { *addr }.ConnectionType);
        println!("Tunnel type: {}", unsafe { *addr }.TunnelType);
        println!("DHCPv6 server: {:?}", sockaddr_to_string(unsafe { *addr }.Dhcpv6Server.lpSockaddr));

        let duid_length = usize::try_from(unsafe { *addr }.Dhcpv6ClientDuidLength).unwrap()
            .min(unsafe { *addr }.Dhcpv6ClientDuid.len());
        let duid = &unsafe { *addr }.Dhcpv6ClientDuid[..duid_length];
        println!("DHCPv6 client DUID: {:?}", duid);
        println!("DHCPv6 IAID: {}", unsafe { *addr }.Dhcpv6Iaid);

        println!("DNS suffixes:");
        let mut sfx = unsafe { (*addr).FirstDnsSuffix };
        while !sfx.is_null() {
            let string_copy = unsafe { *sfx }.String;
            let nul_index = string_copy
                .iter()
                .position(|w| *w == 0x0000)
                .unwrap_or(string_copy.len());
            let string_slice = &string_copy[..nul_index];
            let string = String::from_utf16(string_slice)
                .expect("invalid UTF-16 DNS suffix");
            println!("  Suffix: {:?}", string);

            sfx = unsafe { *sfx }.Next;
        }

        println!();
        addr = unsafe { *addr }.Next;
    }
    drop(buffer);
}
