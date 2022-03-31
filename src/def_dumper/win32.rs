//! Functions used for handling Windows files

use super::byteorder::{ByteOrder, LittleEndian, BigEndian};

#[derive(Debug)]
pub struct PESectionPtr {
    pub offset : usize,
    pub size : usize,
    pub address : u32
}

use std::collections::BTreeMap;

#[derive(Debug)]
pub struct PEData {
    pub creation_date : u32,
    pub checksum : u32,
    pub version : Option<String>,
    pub sections : BTreeMap<String, PESectionPtr>
}

/// Read the PE header and get the data sections from a Win32 EXE
pub fn get_win32_exe_sections(file_data: &[u8]) -> Option<PEData> {
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
    let creation_date = LittleEndian::read_u32(&koffing[4..]);
    let section_count = LittleEndian::read_u16(&koffing[2..]) as usize;
    let opt_header_size = LittleEndian::read_u16(&koffing[16..]);
    let opt_header = &koffing[20..];
    let checksum = LittleEndian::read_u32(&opt_header[64..]);
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

    let mut sections = BTreeMap::<String, PESectionPtr>::new();
    for i in 0..section_count {
        let section = &sections_data[i*40..];

        let pointer_to_raw_data = LittleEndian::read_u32(&section[20..]) as usize;
        let size_of_raw_data = LittleEndian::read_u32(&section[16..]) as usize;
        let virtual_address = LittleEndian::read_u32(&section[12..]) + image_base;
        sections.insert(super::read_string(&section)?, PESectionPtr { offset: pointer_to_raw_data, size: size_of_raw_data, address: virtual_address });
    }

    struct RSRCEntry {
        name : u32,
        data : u32
    }

    struct RSRCTable {
        //named_entries: Vec<RSRCEntry>,
        id_entries: Vec<RSRCEntry>
    }

    impl RSRCTable {
        fn from_buffer(buffer : &[u8]) -> RSRCTable {
            let mut table = &buffer[16..];


            /*
            let number_of_named_entries = LittleEndian::read_u16(&buffer[12..]) as usize;
            let mut named_entries = Vec::<RSRCEntry>::new();
            for _ in 0..number_of_named_entries {
                named_entries.push(RSRCEntry {
                    name : LittleEndian::read_u32(&table[0..]),
                    data : LittleEndian::read_u32(&table[4..])
                });

                table = &table[8..];
            }
            */

            let number_of_id_entries = LittleEndian::read_u16(&buffer[14..]) as usize;
            let mut id_entries = Vec::<RSRCEntry>::new();
            for _ in 0..number_of_id_entries {
                id_entries.push(RSRCEntry {
                    name : LittleEndian::read_u32(&table[0..]),
                    data : LittleEndian::read_u32(&table[4..])
                });

                table = &table[8..];
            }

            RSRCTable {
                //named_entries: named_entries,
                id_entries: id_entries
            }
        }
    }

    let mut rsrc_version = None;

    match sections.get(".rsrc") {
        Some(n) => {
            let rsrc_data = &file_data[n.offset..n.offset + n.size];
            let rsrc_addr = LittleEndian::read_u32(&opt_header[112..]) as usize;

            for i in RSRCTable::from_buffer(&rsrc_data[0..]).id_entries {
                if i.name == 0x10 {
                    for j in RSRCTable::from_buffer(&rsrc_data[(i.data as usize) & 0x7FFFFFFF..]).id_entries {
                        if j.name == 0x1 {
                            for k in RSRCTable::from_buffer(&rsrc_data[(j.data as usize) & 0x7FFFFFFF..]).id_entries {
                                if k.name == 0x409 {
                                    let table_entry = &rsrc_data[k.data as usize..];
                                    let base_addr = LittleEndian::read_u32(&table_entry[0..]);
                                    let size = LittleEndian::read_u32(&table_entry[4..]);
                                    let offset = base_addr as usize - rsrc_addr;

                                    fn u16_len(what : &str) -> usize {
                                        return (what.len() + 1) * 2;
                                    }

                                    fn calculate_32_bit_padding(offset: usize) -> usize {
                                        return (4 - (offset % 4)) % 4;
                                    }

                                    // VS_VERSIONINFO - https://docs.microsoft.com/en-us/windows/win32/menurc/vs-versioninfo
                                    let vs_vi_table = &rsrc_data[offset..offset+size as usize];

                                    // Get the length of the key
                                    let vs_vi_len = u16_len("VS_VERSION_INFO");
                                    let vs_vi_pre_key_offset = offset + 6; // offset of where the key is
                                    let vs_vi_post_key_offset = vs_vi_pre_key_offset + vs_vi_len; // offset of what will be after the key
                                    let vs_vi_post_key_offset_padded = vs_vi_post_key_offset + calculate_32_bit_padding(vs_vi_post_key_offset); // + padding
                                    
                                    // Get the offset to the StringFileInfo
                                    let vs_vi_value_length = LittleEndian::read_u16(&vs_vi_table[2..]) as usize;
                                    let vs_vi_post_value_offset = vs_vi_post_key_offset_padded + vs_vi_value_length; // offset of what will be after the value
                                    let vs_vi_post_value_offset_padded = vs_vi_post_value_offset + calculate_32_bit_padding(vs_vi_post_value_offset); // + padding

                                    // Return the size of the structure, the size of the header, and the key and value
                                    struct ParsedThing {
                                        key : String,
                                        value : Option<String>,
                                        value_offset : usize,
                                        structure_size : usize
                                    }
                                    fn parse_thing(data: &[u8], offset: usize, parse_value_as_string: bool) -> ParsedThing {
                                        fn naive_utf16_string_reader(data: &[u8], mut data_offset: usize) -> String {
                                            let mut v = Vec::<u8>::new();
                                            loop {
                                                let word = LittleEndian::read_u16(&data[data_offset..]);
                                                if word == 0 {
                                                    break;
                                                }
                                                data_offset += 2;
                                                v.push((word & 0xFF) as u8);
                                            }
                                            std::ffi::CString::new(v).unwrap().to_string_lossy().to_string()
                                        }

                                        let length = LittleEndian::read_u16(&data[offset..]);
                                        let key_start = offset + 6;
                                        let key = naive_utf16_string_reader(&data, key_start);
                                        let key_end = key_start + (key.len() * 2 + 1);

                                        let value_start = calculate_32_bit_padding(key_end) + key_end;
                                        let value = if parse_value_as_string {
                                            Some(naive_utf16_string_reader(&data, value_start))
                                        }
                                        else {
                                            None
                                        };

                                        ParsedThing {
                                            key: key,
                                            value: value,
                                            value_offset: value_start,
                                            structure_size: length as usize
                                        }
                                    }

                                    // Now for the StringFileInfo
                                    let string_file_info = parse_thing(&rsrc_data, vs_vi_post_value_offset_padded, false);
                                    if string_file_info.key != "StringFileInfo" {
                                        eprintln!("Expected StringFileInfo. Got {} instead!", string_file_info.key);
                                        break;
                                    }

                                    // Moving on...
                                    let string_file_info_value_start = string_file_info.value_offset;
                                    let string_file_info_value_end = vs_vi_post_value_offset_padded + string_file_info.structure_size;

                                    // This will shrink as we read more data
                                    let mut string_file_info_value_data = &rsrc_data[string_file_info_value_start..string_file_info_value_end];
                                    while string_file_info_value_data.len() != 0 {
                                        // Parse the table
                                        let next_table = parse_thing(&string_file_info_value_data, 0, false);
                                        let mut table_data = &string_file_info_value_data[next_table.value_offset..next_table.structure_size];
                                        let mut key_values = BTreeMap::<String, String>::new();
                                        while table_data.len() > 0 {
                                            let string = parse_thing(&table_data, 0, true);
                                            assert!(string.structure_size != 0);

                                            let padding_if_needed = calculate_32_bit_padding(string.structure_size);
                                            table_data = &table_data[string.structure_size..];
                                            key_values.insert(string.key, string.value.unwrap());

                                            // Make sure each string is padded
                                            if table_data.len() > 0 {
                                                table_data = &table_data[padding_if_needed..];
                                            }
                                        }
                                        string_file_info_value_data = &string_file_info_value_data[next_table.structure_size..];
                                        if next_table.key == "040904b0" {
                                            match key_values.get("FileVersion") {
                                                Some(n) => {
                                                    rsrc_version = Some(n.to_owned().replace(" ", "").replace(",",".")); // Some exes are formated 0, 1, 2, 3 instead of 0.1.2.3
                                                },
                                                None => ()
                                            }
                                            break;
                                        }
                                    }
                                }
                            }
                            break;
                        }
                    }
                    break;
                }
            }
        },
        None => ()
    }

    Some(PEData {
        creation_date: creation_date,
        checksum: checksum,
        version: rsrc_version,
        sections: sections
    })
}
