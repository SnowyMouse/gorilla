//! Functions used for handling Windows files

use super::byteorder::{ByteOrder, LittleEndian, BigEndian};

pub struct PESectionPtr {
    pub offset : usize,
    pub size : usize,
    pub address : u32
}

/// Read the PE header and get the data sections from a Win32 EXE
pub fn get_win32_exe_sections(file_data: &[u8]) -> Option<Vec<PESectionPtr>> {
    // Get the PE header
    let pe_header = &file_data[LittleEndian::read_u32(&file_data[0x3C..]) as usize..];
    if BigEndian::read_u32(pe_header) != 0x50450000 { // check PE magic
        eprintln!("Not a PE file");
        return None
    }

    // Get coff stuff
    let koffing = &pe_header[4..];
    let machine_type = LittleEndian::read_u16(&koffing);
    if machine_type != 0x14C {
        eprint!("Not a i386 exe... ");
        if machine_type == 0x8664 {
            eprintln!("(...it's 64-bit x86!)");
        }
        else {
            eprintln!("(I don't know what type it is! ({:02X}))", machine_type);
        }
        return None
    }
    let section_count = LittleEndian::read_u16(&koffing[2..]) as usize;
    let opt_header_size = LittleEndian::read_u16(&koffing[16..]);
    let opt_header = &koffing[20..];
    let pe_type = LittleEndian::read_u16(&opt_header);
    let win_specific_fields_opt = &opt_header[24..];
    let image_base;
    if pe_type == 0x10B {
        image_base = LittleEndian::read_u32(&win_specific_fields_opt[4..]);
    }
    else if pe_type == 0x20B {
        //image_base = LittleEndian::read_u32(&win_specific_fields_opt);
        eprintln!("Can't handle PE32+. Sorry!");
        return None;
    }
    else {
        eprintln!("Unknown PE32/PE32+ type");
        return None
    }

    // Add each section
    let sections_data = &opt_header[opt_header_size as usize..];

    let mut sections = Vec::<PESectionPtr>::new();
    for i in 0..section_count {
        let section = &sections_data[i*40..];
        let pointer_to_raw_data = LittleEndian::read_u32(&section[20..]) as usize;
        let size_of_raw_data = LittleEndian::read_u32(&section[16..]) as usize;
        let virtual_address = LittleEndian::read_u32(&section[12..]) + image_base;
        sections.push(PESectionPtr { offset: pointer_to_raw_data, size: size_of_raw_data, address: virtual_address });
    }

    Some(sections)
}
