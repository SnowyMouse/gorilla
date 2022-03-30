//! Definition dumper

extern crate serde;
extern crate serde_json;

use std::ffi::CString;
use std::collections::BTreeMap;

mod block;
use self::block::*;

#[macro_use]
mod signature_scan;
use self::signature_scan::*;

mod win32;
use self::win32::*;

extern crate chrono;
use self::chrono::prelude::{DateTime, Utc, NaiveDateTime};

extern crate byteorder;
use self::byteorder::{ByteOrder, LittleEndian};

fn translate_ptr(pointers: &[PESectionPtr], ptr: u32) -> Option<usize> {
    for ref i in pointers {
        if i.address <= ptr && (i.address + i.size as u32) > ptr {
            return Some(ptr as usize - i.address as usize + i.offset)
        }
    }
    None
}

fn read_string(data : &[u8]) -> Option<String> {
    // Find the null byte, make CString from it
    Some(CString::from_vec_with_nul(data[..data.iter().position(|&b| b == 0)?+1].to_vec()).unwrap().to_str().unwrap().to_owned())
}

#[derive(serde::Serialize)]
struct Group {
    supergroup: Option<String>,
    fourcc: u32,
    block: Block
}

/// Dump all definitions into a JSON
pub fn dump_definitions_into_json(file_data: &[u8]) -> Option<Vec<u8>> {
    let pe_data = get_win32_exe_sections(file_data)?;

    let pe_sections = &pe_data.sections;

    // Find the group thing
    let (group_count, group_array, use_old_offsets) = match signature_scan(file_data, &sig!(0x39, 0x0C, 0x85, -1, -1, -1, -1, 0x74, 0x14, 0x46, 0x66, 0x83, 0xFE, -1, 0x72, 0xED)) {
        Some(n) => Some((file_data[n + 13] as usize, &file_data[translate_ptr(pe_sections, LittleEndian::read_u32(&file_data[n + 3..]))?..], false)),
        None => match signature_scan(file_data, &sig!(0x39, 0x14, 0xB5, -1, -1, -1, -1, 0x74, 0x09, 0x41, 0x66, 0x83, 0xF9, -1, 0x72, 0xED)) {
            Some(n) => Some((file_data[n + 13] as usize, &file_data[translate_ptr(pe_sections, LittleEndian::read_u32(&file_data[n + 3..]))?..], true)),
            None => None
        }
    }?;

    // Get all FourCCs and group names
    let (group_fourccs, group_names) = {
        let mut fourcc_arr = BTreeMap::<u32, String>::new();
        let mut group_names = Vec::<String>::new();
        group_names.reserve(group_count);

        for g in 0..group_count {
            let group_struct = &file_data[translate_ptr(pe_sections, LittleEndian::read_u32(&group_array[g*4..]))?..];
            let group_name = read_string(&file_data[translate_ptr(pe_sections, LittleEndian::read_u32(&group_struct[0..]))?..])?;
            let group_fourcc = LittleEndian::read_u32(&group_struct[8..]);
            fourcc_arr.insert(group_fourcc, group_name.clone());
            group_names.push(group_name);
        }
        (fourcc_arr, group_names)
    };

    // Go through each group
    let mut group_blocks = BTreeMap::<String, Group>::new();
    for g in 0..group_count {
        let group_struct = &file_data[translate_ptr(pe_sections, LittleEndian::read_u32(&group_array[g*4..]))?..];
        let group_name = &group_names[g];
        let block_struct = &file_data[translate_ptr(pe_sections, LittleEndian::read_u32(&group_struct[0x18..]))?..];

        fn recursively_parse_block(block_data: &[u8], file_data: &[u8], pe_sections: &[PESectionPtr], groups: &BTreeMap::<u32, String>, use_old_offsets: bool) -> Option<Block> {
            let mut b = Block::default();

            // Read the name?
            if !use_old_offsets {
                b.name = Some(read_string(&file_data[translate_ptr(pe_sections, LittleEndian::read_u32(&block_data[4..]))?..])?)
            }

            // Offsets!
            let maximum_offset = if use_old_offsets { 0x8 } else { 0xC };
            let length_offset = if use_old_offsets { 0xC } else { 0x14 };
            let block_offset = if use_old_offsets { 0x14 } else { 0x1C };
            let entry_length = if use_old_offsets { 0xC } else { 0x10 };

            b.maximum = LittleEndian::read_u32(&block_data[maximum_offset..]) as usize;
            b.length = LittleEndian::read_u32(&block_data[length_offset..]) as usize;

            // Each field!
            let mut fields = &file_data[translate_ptr(pe_sections, LittleEndian::read_u32(&block_data[block_offset..]))?..];
            loop {
                let mut field_type = LittleEndian::read_u32(&fields[0..]);

                if use_old_offsets && field_type >= 0x1 {
                    field_type += 1;
                }

                // The end
                match field_type {
                    0x2D => break,

                    n if n < 0x2D => {
                        // Get the name
                        let ptr = LittleEndian::read_u32(&fields[4..]);
                        let name = if ptr != 0 {
                            Some(read_string(&file_data[translate_ptr(pe_sections, ptr)?..])?)
                        }
                        else {
                            None
                        };
                        let alt = LittleEndian::read_u32(&fields[8..]);

                        // Get the block type
                        let block_type = match n {
                            0x00 => BlockFieldType::Primitive("string"),
                            // 0x01 => Unused,
                            0x02 => BlockFieldType::Primitive("int8"),
                            0x03 => BlockFieldType::Primitive("int16"),
                            0x04 => BlockFieldType::Primitive("int32"),
                            0x05 => BlockFieldType::Primitive("float_angle"),
                            0x06 => BlockFieldType::Primitive("fourcc"),

                            // Enums and flags
                            0x07 | 0x08 | 0x09 | 0x0A => {
                                // Get the number of fields
                                let mut fields = Vec::<FieldName>::new();
                                let str_array_header = &file_data[translate_ptr(pe_sections, alt)?..];
                                let field_count = LittleEndian::read_u32(&str_array_header[0..]) as usize;
                                fields.reserve(field_count);
                                let mut field_array = &file_data[translate_ptr(pe_sections, LittleEndian::read_u32(&str_array_header[4..]))?..];
                                
                                // Go through each field
                                for _ in 0..field_count {
                                    fields.push(FieldName::new(&read_string(&file_data[translate_ptr(pe_sections, LittleEndian::read_u32(&field_array))?..])?));
                                    field_array = &field_array[4..];
                                }

                                // Done!
                                match n {
                                    0x07 => BlockFieldType::Enum(fields),
                                    0x08 => BlockFieldType::Flags("int32", fields),
                                    0x09 => BlockFieldType::Flags("int16", fields),
                                    0x0A => BlockFieldType::Flags("int8", fields),
                                    _ => unreachable!()
                                }
                            },

                            0x0B => BlockFieldType::Primitive("point2d_int"),
                            0x0C => BlockFieldType::Primitive("rectangle"),
                            0x0D => BlockFieldType::Primitive("color_rgb_int"),
                            0x0E => BlockFieldType::Primitive("color_argb_int"),

                            0x0F => BlockFieldType::Primitive("float"),
                            0x10 => BlockFieldType::Primitive("float_clamped"), // 0-1 enforced

                            0x11 => BlockFieldType::Primitive("point2d"),
                            0x12 => BlockFieldType::Primitive("point3d"),
                            0x13 => BlockFieldType::Primitive("vector2d"),
                            0x14 => BlockFieldType::Primitive("vector3d"),
                            0x15 => BlockFieldType::Primitive("quaternion"),
                            0x16 => BlockFieldType::Primitive("euler2d"),
                            0x17 => BlockFieldType::Primitive("euler3d"),
                            0x18 => BlockFieldType::Primitive("plane2d"),
                            0x19 => BlockFieldType::Primitive("plane3d"),
                            0x1A => BlockFieldType::Primitive("color_rgb"),
                            0x1B => BlockFieldType::Primitive("color_argb"),
                            0x1C => BlockFieldType::Primitive("color_hsv"),  // unused by anything
                            0x1D => BlockFieldType::Primitive("color_ahsv"), // unused by anything

                            0x1E => BlockFieldType::Range("int16"),
                            0x1F => BlockFieldType::Range("float_angle"),
                            0x20 => BlockFieldType::Range("float"),
                            0x21 => BlockFieldType::Range("float_clamped"),

                            0x22 => {
                                let reference_data = &file_data[translate_ptr(pe_sections, alt)?..];

                                // If this is 0xFFFFFFFF it can be anything (or a set list at 0x8 if nonzero)
                                // Also if it's the FourCC of a supergroup (e.g. shader), it will allow you to reference any of that
                                let expected_fourcc = LittleEndian::read_u32(&reference_data[4..]);
                                let list = LittleEndian::read_u32(&reference_data[8..]);

                                let mut expected_types = Vec::<String>::new();

                                if expected_fourcc != 0xFFFFFFFF {
                                    expected_types.push(groups.get(&expected_fourcc)?.to_owned());
                                }
                                else if list == 0 {
                                    for (_,v) in groups {
                                        expected_types.push(v.to_owned());
                                    }
                                }
                                else {
                                    let mut fourccs_allowed = &file_data[translate_ptr(pe_sections, list)?..];
                                    loop {
                                        let fourcc = LittleEndian::read_u32(fourccs_allowed);
                                        if fourcc == 0xFFFFFFFF {
                                            break;
                                        }
                                        expected_types.push(groups.get(&fourcc)?.to_owned());
                                        fourccs_allowed = &fourccs_allowed[4..];
                                    }
                                }

                                BlockFieldType::Reference(expected_types)
                            },
                            
                            0x23 => BlockFieldType::Block(recursively_parse_block(&file_data[translate_ptr(pe_sections, alt)?..], file_data, pe_sections, groups, use_old_offsets)?),
                            
                            0x24 | 0x25 => {
                                let tag_data_info = &file_data[translate_ptr(pe_sections, alt)?..];
                                let block = read_string(&file_data[translate_ptr(pe_sections, LittleEndian::read_u32(&tag_data_info))?..])?;
                                BlockFieldType::Index(block, "no-name".to_owned())
                            },

                            0x26 => {
                                let tag_data_info = &file_data[translate_ptr(pe_sections, alt)?..];
                                let name = read_string(&file_data[translate_ptr(pe_sections, LittleEndian::read_u32(&tag_data_info))?..])?;
                                BlockFieldType::TagData(name, LittleEndian::read_u32(&tag_data_info[8..]) as usize)
                            },

                            0x27 => BlockFieldType::PrimitiveArray("int32", alt as usize),
                            0x28 => BlockFieldType::Padding("int32", 1),
                            0x29 => BlockFieldType::Padding("int8", alt as usize),
                            0x2A => BlockFieldType::Padding("int8", alt as usize),

                            0x2B => BlockFieldType::Section(read_string(&file_data[translate_ptr(pe_sections, alt)?..])?),

                            0x2C => BlockFieldType::Padding("int16", 1),

                            n => BlockFieldType::Unknown(n, alt)
                        };
                        b.fields.push(Field {
                            name : match name {
                                Some(n) => Some(FieldName::new(&n)),
                                None => None
                            },
                            block_type : block_type
                        });
                    }

                    _ => {
                        eprintln!("Unknown field type 0x{:04X}", field_type);
                        return None;
                    }
                }

                fields = &fields[entry_length..];
            }            

            Some(b)
        }

        group_blocks.insert(group_name.to_owned(), Group {
            supergroup: match LittleEndian::read_u32(&group_struct[0xC..]) {
                0xFFFFFFFF => None,
                n => Some(group_fourccs.get(&n)?.to_owned())
            },
            fourcc: LittleEndian::read_u32(&group_struct[8..]),
            block: recursively_parse_block(block_struct, file_data, pe_sections, &group_fourccs, use_old_offsets)?
        });
    }

    #[derive(serde::Serialize)]
    struct FinalJSONOutput {
        exe_date: String,
        exe_checksum: u32,
        groups: BTreeMap<String, Group>
    }

    match serde_json::to_vec_pretty(&FinalJSONOutput {
        exe_date: DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(pe_data.creation_date as i64, 0), Utc).format("%Y-%m-%dT%T").to_string(),
        exe_checksum: pe_data.checksum,
        groups: group_blocks
    }) {
        Ok(n) => Some(n),
        Err(_) => None
    }
}
