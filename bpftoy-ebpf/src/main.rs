#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_get_current_comm},
    macros::{kprobe, map},
    maps::PerfEventArray,
    programs::ProbeContext,
};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CredEvent {
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub gid: u32,
    pub euid: u32,
    pub egid: u32,
    pub suid: u32,
    pub sgid: u32,
    pub comm: [u8; 16],
    pub event_type: u32,
}

#[map]
static CRED_EVENTS: PerfEventArray<CredEvent> = PerfEventArray::new(0);

const EVENT_COMMIT_CREDS: u32 = 1;
const EVENT_PREPARE_CREDS: u32 = 2;

#[kprobe]
pub fn trace_creds(ctx: ProbeContext) -> u32 {
    match try_trace_creds(ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn try_trace_creds(ctx: ProbeContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    
    let pid = (pid_tgid & 0xFFFFFFFF) as u32;
    let tgid = (pid_tgid >> 32) as u32;
    let uid = (uid_gid & 0xFFFFFFFF) as u32;
    let gid = (uid_gid >> 32) as u32;
    
    let comm = match bpf_get_current_comm() {
        Ok(c) => c,
        Err(_) => [0u8; 16],
    };
    
    // Filter out some noisy system processes
    // Only report interesting credential changes
    let comm_str = &comm[..];
    
    // Skip kernel threads (usually have names in brackets or are system daemons)
    if comm_str.starts_with(b"kthread") || 
       comm_str.starts_with(b"ksoftirqd") ||
       comm_str.starts_with(b"migration") ||
       comm_str.starts_with(b"rcu_") ||
       pid < 100 {  // Skip very low PID system processes
        return Ok(0);
    }
    
    // Only report if there's an actual UID/GID change or if it's a potentially interesting process
    let is_interesting = uid == 0 ||  // Root operations
                        gid == 0 ||   // Root group
                        comm_str.starts_with(b"sudo") ||
                        comm_str.starts_with(b"su") ||
                        comm_str.starts_with(b"ssh") ||
                        comm_str.starts_with(b"login") ||
                        comm_str.starts_with(b"passwd");
    
    if is_interesting {
        let event = CredEvent {
            pid,
            tgid,
            uid,
            gid,
            euid: uid,
            egid: gid,
            suid: uid,
            sgid: gid,
            comm,
            event_type: EVENT_COMMIT_CREDS,
        };
        
        let _ = CRED_EVENTS.output(&ctx, &event, 0);
    }
    
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}