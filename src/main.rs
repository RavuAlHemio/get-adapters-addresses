use std::alloc::{alloc_zeroed, dealloc, Layout};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::ptr::null;

use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_SUCCESS};
use windows_sys::Win32::Globalization::{CP_ACP, MB_ERR_INVALID_CHARS, MB_PRECOMPOSED, MultiByteToWideChar};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetAdaptersAddresses, GAA_FLAG_INCLUDE_ALL_COMPARTMENTS, GAA_FLAG_INCLUDE_ALL_INTERFACES,
    GAA_FLAG_INCLUDE_GATEWAYS, GAA_FLAG_INCLUDE_PREFIX, GAA_FLAG_INCLUDE_TUNNEL_BINDINGORDER,
    GAA_FLAG_INCLUDE_WINS_INFO, IP_ADAPTER_ADDRESSES_LH,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR};


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


fn pstr_to_string(pstr: windows_sys::core::PSTR) -> String {
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

    String::from_utf16(&utf16_buf)
        .expect("MultiByteToWideChar returned invalid UTF-16 data")
}

fn sockaddr_to_string(sockaddr: &SOCKADDR) -> String {
    match sockaddr.sa_family {
        AF_INET => {
            let mut array = [0u8; 4];
            for (ab, sab) in array.iter_mut().zip(sockaddr.sa_data.iter()) {
                *ab = *sab as u8;
            }
            Ipv4Addr::from(array).to_string()
        },
        AF_INET6 => {
            let mut array = [0u8; 16];
            for (ab, sab) in array.iter_mut().zip(sockaddr.sa_data.iter()) {
                *ab = *sab as u8;
            }
            Ipv6Addr::from(array).to_string()
        },
        other => {
            format!("unknown address family {:#06X} address {:?}", other, sockaddr.sa_data)
        },
    }
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
        println!("Unicast addresses:");

        let mut uc_addr = unsafe { (*addr).FirstUnicastAddress };
        while !uc_addr.is_null() {
            println!("  Address");
            println!("    Flags: {}", unsafe { (*uc_addr).Anonymous.Anonymous }.Flags);
            println!("    Length: {}", unsafe { (*uc_addr).Anonymous.Anonymous }.Length);
            println!("    Address: {}", sockaddr_to_string(&unsafe { *(*uc_addr).Address.lpSockaddr }));

            uc_addr = unsafe { *uc_addr }.Next;
        }

        addr = unsafe { *addr }.Next;
    }
    drop(buffer);
}
