//#[macro_use]
//extern crate nom;

extern crate byteorder;
extern crate bit_field;
extern crate itertools;
use byteorder::{LE, ReadBytesExt};
use bit_field::{BitArray, BitField};
use itertools::Itertools;

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
    titleidrange_min: u64,
    titleidrange_max: u64,
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
    titleid: u64,
    lowest_allowed_titleid: u64,
    fs_access_header_offset: u32,
    fs_access_header_size: u32,
    service_access_control_offset: u32,
    service_access_control_size: u32,
    kernel_access_control_offset: u32,
    kernel_access_control_size: u32
}



fn main() {
    use std::fs::File;
    use std::env;
    use std::io::{Read, Seek, SeekFrom};

    let mut npdm_file = File::open(env::args().nth(1).unwrap()).unwrap();
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
        npdm_file.read_exact(&mut std::mem::transmute::<&mut Acid, &mut [u8; std::mem::size_of::<Acid>()]>(&mut acid)[..]);
    }

    let mut aci0_syscalls = [false; 0x80];
    npdm_file.seek(SeekFrom::Start((npdm.aci0_offset + aci0.kernel_access_control_offset) as u64));

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
    npdm_file.seek(SeekFrom::Start((npdm.acid_offset + acid.kernel_access_control_offset) as u64));

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

    print!("[");
    print!("{}", aci0_syscalls.iter()
        .zip(acid_syscalls.iter()).enumerate()
        .filter(|&(_, (i, j))| *i && *j).map(|(idx, _)| format!("{}", idx))
        .join(","));
    println!("]");
}
