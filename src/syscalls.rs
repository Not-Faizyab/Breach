use std::arch::asm;

/// THE WINDOWS VOID: Direct System Call Execution
/// This bypasses ntdll.dll user-mode hooks entirely.
#[cfg(target_os = "windows")]
pub unsafe fn execute_windows_syscall(
    ssn: u32,       // The System Service Number (e.g., 0x08 for NtWriteFile on Win11)
    arg1: usize,    // RCX
    arg2: usize,    // RDX
    arg3: usize,    // R8
    arg4: usize,    // R9
) -> usize {
    let mut nt_status: usize;
    
    // The precise x64 Assembly required to talk directly to the Windows NT Kernel
    asm!(
        "mov r10, rcx", // Windows Kernel convention requires rcx to be moved to r10
        "syscall",      // Drop into Ring 0
        in("eax") ssn,
        in("rcx") arg1,
        in("rdx") arg2,
        in("r8") arg3,
        in("r9") arg4,
        lateout("rax") nt_status, // The kernel returns the NTSTATUS code here
        options(nostack, preserves_flags)
    );
    
    nt_status
}