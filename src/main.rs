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
use byteorder::{LE, ReadBytesExt};
use bit_field::{BitArray, BitField};
use itertools::Itertools;
use std::path::Path;

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

#[derive(Serialize, Deserialize)]
struct Program {
    title_id: u64,
    title_name: String,
    svcs: Vec<u8>,
    hosts_services: Vec<String>,
    accesses_services: Vec<String>
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
        }
    }

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
        title_id: aci0.title_id,
        title_name: title_name,
        svcs: aci0_syscalls.iter()
            .zip(acid_syscalls.iter()).enumerate()
            .filter(|&(_, (i, j))| *i && *j).map(|(idx, _)| idx as u8).collect(),
        hosts_services: hosts_services,
        accesses_services: accesses_services
    }
}

fn main() {
    use std::fs;
    use std::env;
    use walkdir::WalkDir;

    let files = WalkDir::new(env::args().nth(1).unwrap_or(".".to_string())).follow_links(true).into_iter();
    let programs : Vec<Program> = files.filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_name().to_string_lossy().ends_with(".npdm"))
        .map(|file| parse_npdm(file.path()))
        .collect();
    println!("{}", serde_json::to_string_pretty(&programs).unwrap());
}
