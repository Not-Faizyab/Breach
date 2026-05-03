use std::ptr;

// 4C 8B D1 : mov r10, rcx
// B8       : mov eax, [SSN]
const SYSCALL_STUB: [u8; 4] = [0x4C, 0x8B, 0xD1, 0xB8];

/// Hunts for the System Service Number (SSN) of a given ntdll function.
#[cfg(target_os = "windows")]
pub unsafe fn hunt_ssn(function_address: *const u8) -> Option<u32> {
    // We scan the first 32 bytes of the function looking for the syscall stub
    for offset in 0..32 {
        let current_ptr = function_address.add(offset);
        
        // Read 4 bytes from memory
        let bytes = std::slice::from_raw_parts(current_ptr, 4);
        
        if bytes == SYSCALL_STUB {
            // We found the stub! The next 4 bytes contain the SSN.
            // It looks like: B8 [SSN_BYTE_1] [SSN_BYTE_2] 00 00
            let ssn_ptr = current_ptr.add(4) as *const u32;
            let ssn = ptr::read_unaligned(ssn_ptr);
            
            return Some(ssn);
        }
    }
    
    None
}