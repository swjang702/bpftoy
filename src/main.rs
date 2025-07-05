use aya::{
    include_bytes_aligned,
    maps::PerfEventArray,
    programs::KProbe,
    Bpf,
};
use clap::Parser;
use log::info;
use std::convert::TryInto;
use tokio::{signal, task};

#[derive(Debug, Parser)]
struct Args {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
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

const EVENT_COMMIT_CREDS: u32 = 1;
const EVENT_PREPARE_CREDS: u32 = 2;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let _args = Args::parse();

    env_logger::init();

    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../target/bpfel-unknown-none/release/bpftoy"
    ))?;


    // List all programs to debug
    for (name, _) in bpf.programs() {
        println!("Found program: {}", name);
    }
    
    let program: &mut KProbe = bpf.program_mut("kprobe").unwrap().try_into()?;
    program.load()?;
    match program.attach("commit_creds", 0) {
        Ok(_) => println!("Successfully attached to commit_creds"),
        Err(e) => println!("Failed to attach to commit_creds: {}", e),
    }

    let mut perf_array = PerfEventArray::try_from(bpf.map_mut("CRED_EVENTS").unwrap())?;

    let mut handles = Vec::new();
    
    for cpu_id in 0..num_cpus::get() {
        let mut buf = perf_array.open(cpu_id.try_into().unwrap(), None)?;
        
        let handle = task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| bytes::BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();

            loop {
                tokio::select! {
                    _ = tokio::time::sleep(tokio::time::Duration::from_millis(10)) => {
                        match buf.read_events(&mut buffers) {
                            Ok(events) => {
                                for i in 0..events.read {
                                    let buf = &mut buffers[i];
                                    let ptr = buf.as_ptr() as *const CredEvent;
                                    let data = unsafe { ptr.read_unaligned() };
                                    
                                    let comm_str = String::from_utf8_lossy(&data.comm)
                                        .trim_matches('\0')
                                        .to_string();
                                    
                                    let event_name = match data.event_type {
                                        EVENT_COMMIT_CREDS => "COMMIT_CREDS",
                                        EVENT_PREPARE_CREDS => "PREPARE_CREDS",
                                        _ => "UNKNOWN",
                                    };
                                    
                                    println!(
                                        "[{}] Process: {} (PID: {}, TGID: {}) - UID: {}, GID: {}, EUID: {}, EGID: {}",
                                        event_name,
                                        comm_str,
                                        data.pid,
                                        data.tgid,
                                        data.uid,
                                        data.gid,
                                        data.euid,
                                        data.egid
                                    );
                                }
                            }
                            Err(_) => {
                                // Ignore errors and continue
                            }
                        }
                    }
                }
            }
        });
        handles.push(handle);
    }

    println!("Task credential tracer is running. Press Ctrl-C to exit.");

    // Wait for Ctrl+C
    signal::ctrl_c().await?;
    println!("Received Ctrl+C, exiting...");
    
    // Cancel all tasks
    for handle in handles {
        handle.abort();
    }

    Ok(())
}
