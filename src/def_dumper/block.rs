//! Halo-related data and block structs

extern crate serde;
extern crate serde_json;
use self::serde::Serialize;

#[derive(Default)]
pub struct FieldName {
    pub name : String,
    pub hidden : bool,
    pub read_only : bool,
    pub main : bool,
    pub description : Option<String>,
    pub unit : Option<String>
}
impl FieldName {
    pub fn new(name: &str) -> Self {
        let mut f = FieldName::default();

        let mut name_copy = name.to_owned();

        // Hide?
        if name_copy.ends_with("!") {
            f.hidden = true;
            name_copy = name_copy[..name_copy.len()-1].to_owned();
        }

        // Comment?
        match name_copy.find("#") {
            Some(n) => {
                f.description = Some(name_copy[n+1..].to_owned());
                name_copy = name_copy[..n].to_owned();
            },
            None => ()
        }

        // Units?
        match name_copy.find(":") {
            Some(n) => {
                f.unit = Some(name_copy[n+1..].to_owned());
                name_copy = name_copy[..n].to_owned();
            },
            None => ()
        }

        // Read only
        if name_copy.contains("*") {
            f.read_only = true;
            name_copy = name_copy.replace("*", "");
        }

        // Is it the main thing?
        if name_copy.contains("^") {
            f.main = true;
            name_copy = name_copy.replace("^", "");
        }

        // Done
        f.name = name_copy;
        f
    }

    fn serialize_inplace<S>(&self, map: &mut S::SerializeMap) -> Result<(), S::Error> where S: Serializer {
        map.serialize_entry("name", &self.name)?;

        match self.description {
            Some(ref n) => map.serialize_entry("description", n)?,
            None => ()
        };

        if self.read_only {
            map.serialize_entry("read_only", &true)?
        }

        if self.hidden {
            map.serialize_entry("hidden", &true)?
        }

        if self.main {
            map.serialize_entry("main", &true)?
        }

        match self.unit {
            Some(ref n) => map.serialize_entry("unit", n)?,
            None => ()
        };

        Ok(())
    }
}
impl Serialize for FieldName {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer, {
        let mut map = serializer.serialize_map(None)?;
        
        self.serialize_inplace::<S>(&mut map)?;

        map.end()
    }
}

#[derive(Default)]
pub struct Field {
    pub name : Option<FieldName>,
    pub block_type : BlockFieldType
}

#[derive(Default, Serialize)]
pub struct Block {
    pub name : Option<String>,
    pub maximum : usize,
    pub length : usize,
    pub fields : Vec<Field>
}

#[derive(Serialize)]
pub struct Group {
    pub name: String,
    pub supergroup: Option<String>,
    pub fourcc: u32,
    pub block: Block
}

pub enum BlockFieldType {
    Unknown(u32, u32),
    Index(String, String),
    TagData(String, usize),
    Section(String),
    Reference(Vec<String>),
    Primitive(&'static str),
    PrimitiveArray(&'static str, usize),
    Enum(Vec<FieldName>),
    Flags(&'static str, Vec<FieldName>),
    Range(&'static str),
    Padding(&'static str, usize),
    Block(Block)
}
impl std::fmt::Display for BlockFieldType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown(val, alt) => write!(f, "Unknown (0x{:02X}; 0x{:08X})", val, alt),
            Self::TagData(name, max_length) => write!(f, "Tag Data ({}; max length: 0x{:08X})", name, max_length),
            Self::Index(block, block2) => write!(f, "Index ({},{})", block, block2),
            Self::Section(section) => write!(f, "Section ({})", section),
            Self::Reference(types) => write!(f, "Reference ({} type(s))", types.len()),
            Self::Primitive(type_name) => write!(f, "Primitive ({})", type_name),
            Self::PrimitiveArray(type_name, count) => write!(f, "PrimitiveArray ({}x{})", type_name, count),
            Self::Enum(values) => write!(f, "Enum ({} values)", values.len()),
            Self::Flags(size, flags) => write!(f, "Flags ({}; {} field(s))", size, flags.len()),
            Self::Range(type_name) => write!(f, "Range ({})", type_name),
            Self::Padding(type_name, count) => write!(f, "Padding ({}x{})", type_name, count),
            Self::Block(blk) => write!(f, "Block ({})", blk.name.as_ref().unwrap_or(&"no-name".to_owned()))
        }
    }
}

use self::serde::ser::{Serializer, SerializeMap};

impl Serialize for Field {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer, {
        let mut map = serializer.serialize_map(None)?;

        // Serialize the name if present
        match self.name {
            Some(ref n) => {
                n.serialize_inplace::<S>(&mut map)?;
            },
            None => ()
        }

        // Next, serialize the type
        match &self.block_type {
            BlockFieldType::Padding(size, count) => {
                map.serialize_entry("type", "padding")?;
                map.serialize_entry("size", size)?;
                map.serialize_entry("count", count)?;
            },
            BlockFieldType::Index(reference_a,_) => {
                map.serialize_entry("type", "index")?;
                map.serialize_entry("reference", reference_a)?;
            },
            BlockFieldType::TagData(data_type, max_length) => {
                map.serialize_entry("type", "tag_data")?;
                map.serialize_entry("data_type", data_type)?;
                map.serialize_entry("max_length", max_length)?;
            },
            BlockFieldType::Section(description) => {
                map.serialize_entry("type", "section")?;
                map.serialize_entry("description", description)?;
            },
            BlockFieldType::Reference(allowed_groups) => {
                map.serialize_entry("type", "tag_reference")?;
                map.serialize_entry("allowed_groups", allowed_groups)?;
            },
            BlockFieldType::Primitive(primitive_type) => {
                map.serialize_entry("type", primitive_type)?;
            },
            BlockFieldType::PrimitiveArray(primitive_type, count) => {
                map.serialize_entry("type", primitive_type)?;
                map.serialize_entry("count", count)?;
            },
            BlockFieldType::Enum(values) => {
                map.serialize_entry("type", "enum")?;
                map.serialize_entry("options", values)?;
            },
            BlockFieldType::Flags(size, values) => {
                map.serialize_entry("type", "bitfield")?;
                map.serialize_entry("size", size)?;
                map.serialize_entry("fields", values)?;
            },
            BlockFieldType::Range(primitive_type) => {
                map.serialize_entry("type", primitive_type)?;
                map.serialize_entry("bounds", &true)?;
            },
            BlockFieldType::Block(block) => {
                map.serialize_entry("type", "block")?;
                map.serialize_entry("block", block)?;
            },
            BlockFieldType::Unknown(a,_) => {
                map.serialize_entry("type", "unknown")?;
                map.serialize_entry("type_number", a)?;
            }
        }

        map.end()
    }
}

impl Default for BlockFieldType {
    fn default() -> Self {
        Self::Unknown(0xFFFFFFFF, 0xFFFFFFFF)
    }
}
