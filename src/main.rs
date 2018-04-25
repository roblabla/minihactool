//#[macro_use]
//extern crate nom;

extern crate serde_json;
#[macro_use]
extern crate serde_derive;
extern crate serde;

extern crate walkdir;
extern crate byteorder;
extern crate bit_field;
extern crate itertools;
use byteorder::{LE, ReadBytesExt, WriteBytesExt, ByteOrder};
use bit_field::{BitArray, BitField};
use itertools::Itertools;
use std::path::Path;
use std::collections::HashMap;
use std::io::{Write, Seek};

#[repr(C, packed)]
struct Npdm {
    magic: u32,
    unk1: u32,
    unk2: u32,
    mmu_flags: u8,
    unk3: u8,
    main_thread_prio: u8,
    default_cpu_id: u8,
    unk4: u64,
    process_category: u32,
    main_stack_size: u32,
    title_name: [u8; 0x50],
    aci0_offset: u32,
    aci0_size: u32,
    acid_offset: u32,
    acid_size: u32
}

#[repr(C, packed)]
struct Acid {
    signature: [u8; 0x100],
    pubkey: [u8; 0x100],
    magic: u32,
    size_field: u32,
    unk1: u32,
    flags: u32,
    title_id_range_min: u64,
    title_id_range_max: u64,
    fs_access_control_offset: u32,
    fs_access_control_size: u32,
    service_access_control_offset: u32,
    service_access_control_size: u32,
    kernel_access_control_offset: u32,
    kernel_access_control_size: u32,
    padding: [u8; 8]
}

#[repr(C, packed)]
#[derive(Debug)]
struct Aci0 {
    magic: u32,
    unk1: u32,
    unk2: u32,
    unk3: u32,
    title_id: u64,
    lowest_allowed_title_id: u64,
    fs_access_header_offset: u32,
    fs_access_header_size: u32,
    service_access_control_offset: u32,
    service_access_control_size: u32,
    kernel_access_control_offset: u32,
    kernel_access_control_size: u32
}

#[repr(C, packed)]
struct FSAccessHeader {
    version: u8,
    padding: [u8; 3],
    permissions_bitmask: u64,
    unk1: u32, // Usually 0x1C
    unk2: u32, // Usually 0
    unk3: u32, // Usually 0x1C
    unk4: u32  // Usually 0
}

#[repr(C, packed)]
struct FSAccessControl {
    version: u8,
    padding: [u8; 3],
    permissions_bitmask: u64,
    unk1: [u8; 0x20] // All zeroes
}

#[derive(Serialize, Deserialize, Debug)]
struct KCap {
    //highest_cpu_allowed: u8,
    //lowest_cpu_allowed: u8,
    //highest_allowed_thread_prio: u8,
    //lowest_allowed_thread_prio: u8,
    // MapIo
    // MapNormal
    // InterruptPair
    // ApplicationType
    // KernelRelease
    handle_table_size: u64,
    //can_be_debugged: bool,
    //can_debug_others: bool,
    #[serde(serialize_with = "ordered_syscalls")]
    syscalls: HashMap<String, u64>
}

fn ordered_syscalls<S>(value: &HashMap<String, u64>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    use serde::ser::SerializeMap;

    let mut map = serializer.serialize_map(Some(value.len()))?;
    let mut elems : Vec<(&String, &u64)> = value.iter().collect();
    elems.sort_unstable_by_key(|e| e.1);
    for (k, v) in elems {
        map.serialize_entry(k, v)?;
    }
    map.end()
}

#[derive(Serialize, Deserialize, Debug)]
struct Program {
    name: String,
    title_id: String,
    main_thread_stack_size: String,
    main_thread_priority: u8,
    default_cpu_id: u8,
    process_category: u32,
    mmu_flags: u8,
    kernel_capabilities: KCap,
    //service_capabilities: ServiceCap,
    //fs_capabilities: FSCap
}

fn get_syscall_name(svc: u8) -> Option<&'static str> {
    match svc {
        0x01 => Some("svcSetHeapSize"),
        0x02 => Some("svcSetMemoryPermission"),
        0x03 => Some("svcSetMemoryAttribute"),
        0x04 => Some("svcMapMemory"),
        0x05 => Some("svcUnmapMemory"),
        0x06 => Some("svcQueryMemory"),
        0x07 => Some("svcExitProcess"),
        0x08 => Some("svcCreateThread"),
        0x09 => Some("svcStartThread"),
        0x0a => Some("svcExitThread"),
        0x0b => Some("svcSleepThread"),
        0x0c => Some("svcGetThreadPriority"),
        0x0d => Some("svcSetThreadPriority"),
        0x0e => Some("svcGetThreadCoreMask"),
        0x0f => Some("svcSetThreadCoreMask"),
        0x10 => Some("svcGetCurrentProcessorNumber"),
        0x11 => Some("svcSignalEvent"),
        0x12 => Some("svcClearEvent"),
        0x13 => Some("svcMapSharedMemory"),
        0x14 => Some("svcUnmapSharedMemory"),
        0x15 => Some("svcCreateTransferMemory"),
        0x16 => Some("svcCloseHandle"),
        0x17 => Some("svcResetSignal"),
        0x18 => Some("svcWaitSynchronization"),
        0x19 => Some("svcCancelSynchronization"),
        0x1a => Some("svcArbitrateLock"),
        0x1b => Some("svcArbitrateUnlock"),
        0x1c => Some("svcWaitProcessWideKeyAtomic"),
        0x1d => Some("svcSignalProcessWideKey"),
        0x1e => Some("svcGetSystemTick"),
        0x1f => Some("svcConnectToNamedPort"),
        0x20 => Some("svcSendSyncRequestLight"),
        0x21 => Some("svcSendSyncRequest"),
        0x22 => Some("svcSendSyncRequestWithUserBuffer"),
        0x23 => Some("svcSendAsyncRequestWithUserBuffer"),
        0x24 => Some("svcGetProcessId"),
        0x25 => Some("svcGetThreadId"),
        0x26 => Some("svcBreak"),
        0x27 => Some("svcOutputDebugString"),
        0x28 => Some("svcReturnFromException"),
        0x29 => Some("svcGetInfo"),
        0x2A => Some("svcFlushEntireDataCache"),
        0x2B => Some("svcFlushDataCache"),
        0x2C => Some("svcMapPhysicalMemory"),
        0x2D => Some("svcUnmapPhysicalMemory"),
        0x2E => Some("svcGetFutureThreadInfo"),
        0x2F => Some("svcGetLastThreadInfo"),
        0x30 => Some("svcGetResourceLimitLimitValue"),
        0x31 => Some("svcGetResourceLimitCurrentValue"),
        0x32 => Some("svcSetThreadActivity"),
        0x33 => Some("svcGetThreadContext3"),
        0x34 => Some("svcWaitForAddress"),
        0x35 => Some("svcSignalToAddress"),
        0x3C => Some("svcDumpInfo"),
        0x3D => Some("svcDumpInfoNew"),
        0x40 => Some("svcCreateSession"),
        0x41 => Some("svcAcceptSession"),
        0x42 => Some("svcReplyAndReceiveLight"),
        0x43 => Some("svcReplyAndReceive"),
        0x44 => Some("svcReplyAndReceiveWithUserBuffer"),
        0x45 => Some("svcCreateEvent"),
        0x48 => Some("svcMapPhysicalMemoryUnsafe"),
        0x49 => Some("svcUnmapPhysicalMemoryUnsafe"),
        0x4A => Some("svcSetUnsafeLimit"),
        0x4B => Some("svcCreateCodeMemory"),
        0x4C => Some("svcControlCodeMemory"),
        0x4D => Some("svcSleepSystem"),
        0x4E => Some("svcReadWriteRegister"),
        0x4F => Some("svcSetProcessActivity"),
        0x50 => Some("svcCreateSharedMemory"),
        0x51 => Some("svcMapTransferMemory"),
        0x52 => Some("svcUnmapTransferMemory"),
        0x53 => Some("vcCreateInterruptEvent"),
        0x54 => Some("svcQueryPhysicalAddress"),
        0x55 => Some("svcQueryIoMapping"),
        0x56 => Some("svcCreateDeviceAddressSpace"),
        0x57 => Some("svcAttachDeviceAddressSpace"),
        0x58 => Some("svcDetachDeviceAddressSpace"),
        0x59 => Some("svcMapDeviceAddressSpaceByForce"),
        0x5A => Some("svcMapDeviceAddressSpaceAligned"),
        0x5B => Some("svcMapDeviceAddressSpace"),
        0x5C => Some("svcUnmapDeviceAddressSpace"),
        0x5D => Some("svcInvalidateProcessDataCache"),
        0x5E => Some("svcStoreProcessDataCache"),
        0x5F => Some("svcFlushProcessDataCache"),
        0x60 => Some("svcDebugActiveProcess"),
        0x61 => Some("svcBreakDebugProcess"),
        0x62 => Some("svcTerminateDebugProcess"),
        0x63 => Some("svcGetDebugEvent"),
        0x64 => Some("svcContinueDebugEvent"),
        0x65 => Some("svcGetProcessList"),
        0x66 => Some("svcGetThreadList"),
        0x67 => Some("svcGetDebugThreadContext"),
        0x68 => Some("svcSetDebugThreadContext"),
        0x69 => Some("svcQueryDebugProcessMemory"),
        0x6A => Some("svcReadDebugProcessMemory"),
        0x6B => Some("svcWriteDebugProcessMemory"),
        0x6C => Some("svcSetHardwareBreakPoint"),
        0x6D => Some("svcGetDebugThreadParam"),
        0x6f => Some("svcGetMemoryInfo"),
        0x70 => Some("svcCreatePort"),
        0x71 => Some("svcManageNamedPort"),
        0x72 => Some("svcConnectToPort"),
        0x73 => Some("svcSetProcessMemoryPermission"),
        0x74 => Some("svcMapProcessMemory"),
        0x75 => Some("svcUnmapProcessMemory"),
        0x76 => Some("svcQueryProcessMemory"),
        0x77 => Some("svcMapProcessCodeMemory"),
        0x78 => Some("svcUnmapProcessCodeMemory"),
        0x79 => Some("svcCreateProcess"),
        0x7A => Some("svcStartProcess"),
        0x7B => Some("svcTerminateProcess"),
        0x7C => Some("svcGetProcessInfo"),
        0x7D => Some("svcCreateResourceLimit"),
        0x7E => Some("svcSetResourceLimitLimitValue"),
        0x7F => Some("svcCallSecureMonitor"),
        _ => None
    }
}

fn parse_npdm(path: &Path) -> Program {
    use std::fs::File;
    use std::env;
    use std::io::{Read, Seek, SeekFrom};

    let mut npdm_file = File::open(path).unwrap();
    let mut npdm : Npdm = unsafe { std::mem::uninitialized() };
    unsafe {
        npdm_file.read_exact(&mut std::mem::transmute::<&mut Npdm, &mut [u8; std::mem::size_of::<Npdm>()]>(&mut npdm)[..]);
    }

    npdm_file.seek(SeekFrom::Start(npdm.aci0_offset as u64));
    if npdm.aci0_size < std::mem::size_of::<Aci0>() as u32 {
        panic!("Wut");
    }
    let mut aci0 : Aci0 = unsafe { std::mem::uninitialized() };
    unsafe {
        npdm_file.read_exact(&mut std::mem::transmute::<&mut Aci0, &mut [u8; std::mem::size_of::<Aci0>()]>(&mut aci0)[..]);
    }

    npdm_file.seek(SeekFrom::Start(npdm.acid_offset as u64));
    if npdm.acid_size < std::mem::size_of::<Acid>() as u32 {
        panic!("Wut");
    }
    let mut acid : Acid = unsafe { std::mem::uninitialized() };
    unsafe {
        npdm_file.read_exact(&mut std::mem::transmute::<&mut Acid, &mut [u8; std::mem::size_of::<Acid>()]>(&mut acid)[..]).unwrap();
    }

    let mut aci0_syscalls = [false; 0x80];
    npdm_file.seek(SeekFrom::Start((npdm.aci0_offset + aci0.kernel_access_control_offset) as u64)).unwrap();

    for i in 0..aci0.kernel_access_control_size/4 {
        let kac = npdm_file.read_u32::<LE>().unwrap();
        if kac & 0b11111 == 0b01111 {
            let mask = kac.get_bits(5..29);
            let table_idx = kac.get_bits(29..32);
            for i in 0..24 {
                if table_idx * 24 + i >= 0x80 {
                    break;
                }
                aci0_syscalls[(table_idx * 24 + i) as usize] = mask & (1 << i) != 0;
            }
        }
    }

    let mut handle_table_size = None;
    let mut acid_syscalls = [false; 0x80];
    npdm_file.seek(SeekFrom::Start((npdm.acid_offset + acid.kernel_access_control_offset) as u64)).unwrap();

    for i in 0..acid.kernel_access_control_size/4 {
        let kac = npdm_file.read_u32::<LE>().unwrap();
        if kac & 0b11111 == 0b01111 {
            let mask = kac.get_bits(5..29);
            let table_idx = kac.get_bits(29..32);
            for i in 0..24 {
                if table_idx * 24 + i >= 0x80 {
                    break;
                }
                acid_syscalls[(table_idx * 24 + i) as usize] = mask & (1 << i) != 0;
            }
        } else if kac & 0b0111111111111111 == 0b0111111111111111 {
            handle_table_size = Some(kac.get_bits(16..26));
        }
    }

    let handle_table_size = handle_table_size.unwrap();

    let mut hosts_services = Vec::new();
    let mut accesses_services = Vec::new();
    npdm_file.seek(SeekFrom::Start((npdm.aci0_offset + aci0.service_access_control_offset) as u64)).unwrap();
    let mut i = 0;
    loop {
        if i >= aci0.service_access_control_size {
            break;
        }
        let control = npdm_file.read_u8().unwrap();
        let size = control.get_bits(0..4) + 1;
        let can_host = control.get_bit(7);
        let mut service_name = vec![0; size as usize];
        npdm_file.read_exact(&mut service_name[..]);
        if can_host {
            hosts_services.push(String::from_utf8(service_name).unwrap());
        } else {
            accesses_services.push(String::from_utf8(service_name).unwrap());
        }
        i += size as u32 + 1;
    }

    let nul_pos = npdm.title_name.iter().position(|e| *e == 0).unwrap();
    let title_name = std::str::from_utf8(&npdm.title_name[..nul_pos]).unwrap().to_string();

    Program {
        name: title_name,
        title_id: format!("{:#x}", aci0.title_id),
        main_thread_stack_size: format!("{:#x}", npdm.main_stack_size),
        main_thread_priority: npdm.main_thread_prio,
        mmu_flags: npdm.mmu_flags,
        default_cpu_id: npdm.default_cpu_id,
        process_category: npdm.process_category,
        kernel_capabilities: KCap {
            handle_table_size: handle_table_size as u64,
            syscalls: aci0_syscalls.iter()
                .zip(acid_syscalls.iter()).enumerate()
                .filter(|&(_, (i, j))| *i && *j).map(|(idx, _)| (get_syscall_name(idx as u8).unwrap_or("svcUNKNOWN").to_string(), idx as u64)).collect(),
        },
        //hosts_services: hosts_services,
        //accesses_services: accesses_services
    }
}

//fn generic_write<W, T>(f: &mut W, t: &mut T) -> std::io::Result<()> where W: Write {
//    unsafe {
//        f.write_all(&std::mem::transmute::<&mut T, &mut [u8; std::mem::size_of::<T>()]>(t)[..])
//    }
//}

fn program_to_npdm<T>(p: Program, f: &mut T) -> std::io::Result<()> where T: Write + Seek {
    use std::io::SeekFrom;

    let mut title_name = [0; 80];
    &title_name[..p.name.as_bytes().len()].copy_from_slice(p.name.as_bytes());
    let mut npdm = Npdm {
        magic: LE::read_u32(&b"META"[..]),
        unk1: 0,
        unk2: 0,
        mmu_flags: p.mmu_flags, // bit 0 : 64-bit instructions, bits 1-3: address space width (1 = 64 bit, 2 = 32 bit)
        unk3: 0,
        main_thread_prio: p.main_thread_priority,
        default_cpu_id: p.default_cpu_id,
        unk4: 0,
        process_category: p.process_category,
        main_stack_size: u32::from_str_radix(&p.main_thread_stack_size[2..], 16).unwrap(),
        title_name,
        aci0_offset: std::mem::size_of::<Npdm>() as u32,
        aci0_size: (std::mem::size_of::<Aci0>() + std::mem::size_of::<FSAccessHeader>()) as u32,
        acid_offset: (std::mem::size_of::<Npdm>() + std::mem::size_of::<Aci0>() + std::mem::size_of::<FSAccessHeader>()) as u32,
        acid_size: (std::mem::size_of::<Acid>() + std::mem::size_of::<FSAccessControl>() + 2 + 8 * 4) as u32,
    };

    unsafe {
        f.write_all(&std::mem::transmute::<&mut Npdm, &mut [u8; std::mem::size_of::<Npdm>()]>(&mut npdm)[..]).unwrap();
    }

    let mut aci0 = Aci0 {
        magic: LE::read_u32(&b"ACI0"[..]),
        unk1: 0,
        unk2: 0,
        unk3: 0,
        title_id: 0x10000000000001c,
        lowest_allowed_title_id: 0x10000000000001c,
        fs_access_header_offset: std::mem::size_of::<Aci0>() as u32,
        fs_access_header_size: std::mem::size_of::<FSAccessHeader>() as u32,
        service_access_control_offset: (std::mem::size_of::<Aci0>() + std::mem::size_of::<FSAccessHeader>() + std::mem::size_of::<Acid>() + std::mem::size_of::<FSAccessControl>()) as u32,
        service_access_control_size: 2,
        kernel_access_control_offset: (std::mem::size_of::<Aci0>() + std::mem::size_of::<FSAccessHeader>() + std::mem::size_of::<Acid>() + std::mem::size_of::<FSAccessControl>() + 2) as u32,
        kernel_access_control_size: 8 * 4
    };

    unsafe {
        f.write_all(&std::mem::transmute::<&mut Aci0, &mut [u8; std::mem::size_of::<Aci0>()]>(&mut aci0)[..]).unwrap();
    }

    let mut fshdr = FSAccessHeader {
        version: 1,
        padding: [0; 3],
        permissions_bitmask: u64::max_value(),
        unk1: 0x1c,
        unk2: 0,
        unk3: 0x1c,
        unk4: 0
    };

    unsafe {
        f.write_all(&std::mem::transmute::<&mut FSAccessHeader, &mut [u8; std::mem::size_of::<FSAccessHeader>()]>(&mut fshdr)[..]).unwrap();
    }

    let mut acid = Acid {
        signature: [0; 0x100],
        pubkey: [0; 0x100],
        magic: LE::read_u32(&b"ACID"[..]),
        size_field: 0,
        unk1: 0,
        flags: 1,
        title_id_range_min: 0,
        title_id_range_max: u64::max_value(),
        fs_access_control_offset: std::mem::size_of::<Acid>() as u32,
        fs_access_control_size: std::mem::size_of::<FSAccessControl>() as u32,
        service_access_control_offset: (std::mem::size_of::<Acid>() + std::mem::size_of::<FSAccessControl>()) as u32,
        service_access_control_size: 2,
        kernel_access_control_offset: (std::mem::size_of::<Acid>() + std::mem::size_of::<FSAccessControl>() + 2) as u32,
        kernel_access_control_size: 8 * 4,
        padding: [0; 8]
    };

    println!("{} {}", acid.kernel_access_control_offset, f.seek(SeekFrom::Current(0)).unwrap());

    unsafe {
        f.write_all(&std::mem::transmute::<&mut Acid, &mut [u8; std::mem::size_of::<Acid>()]>(&mut acid)[..]).unwrap();
    }

    let mut fsacc = FSAccessControl {
        version: 1,
        padding: [0; 3],
        permissions_bitmask: u64::max_value(),
        unk1: [0; 0x20]
    };

    unsafe {
        f.write_all(&std::mem::transmute::<&mut FSAccessControl, &mut [u8; std::mem::size_of::<FSAccessControl>()]>(&mut fsacc)[..]).unwrap();
    }

    // Write the service access control
    f.write_u8(0x80);
    f.write_u8(b'*');

    println!("{}", f.seek(SeekFrom::Current(0)).unwrap());
    // Write the kernel access control
    let mut kernel_flags = 0b0111;
    kernel_flags.set_bits(24..32, 3);
    kernel_flags.set_bits(16..24, 1);
    kernel_flags.set_bits(10..16, 63);
    kernel_flags.set_bits(4..10, 4);
    println!("Writing {:x}", kernel_flags);
    f.write_u32::<LE>(kernel_flags);

    // Handle table
    let mut handle_table = 0b0111111111111111u32;
    handle_table.set_bits(16..26, p.kernel_capabilities.handle_table_size as u32);
    f.write_u32::<LE>(handle_table);

    // Syscalls
    let mut svcs : [bool; 0x80] = [false; 0x80];
    for (_, &v) in p.kernel_capabilities.syscalls.iter() {
        svcs[v as usize] = true;
    }
    for tableidx in 0..6 {
        let mut svcmask = 0b01111u32;
        svcmask.set_bits(29..32, tableidx as u32);
        let mut mask = 0;
        for i in 0..24 {
            if svcs.get(24 * tableidx + i).is_some() {
                mask.set_bit(i, true);
            }
        }
        svcmask.set_bits(5..29, mask);
        f.write_u32::<LE>(svcmask);
    }
    Ok(())
}

fn main() {
    use std::fs;
    use std::env;
    use walkdir::WalkDir;

    let mut program: Program = parse_npdm(Path::new(&env::args().nth(1).unwrap()));
    for i in 1..0x80 {
        let name = get_syscall_name(i as u8);
        if let Some(name) = name {
            program.kernel_capabilities.syscalls.insert(name.to_string(), i);
        }
    }
    program_to_npdm(program, &mut fs::File::create("new.npdm").unwrap());
    //println!("{}", serde_json::to_string_pretty(&program).unwrap());
    //let files = WalkDir::new(env::args().nth(1).unwrap_or(".".to_string())).follow_links(true).into_iter();
    //let programs : Vec<Program> = files.filter_map(|entry| entry.ok())
    //    .filter(|entry| entry.file_name().to_string_lossy().ends_with(".npdm"))
    //    .map(|file| parse_npdm(file.path()))
    //    .collect();
    //println!("{}", serde_json::to_string_pretty(&programs).unwrap());
}
