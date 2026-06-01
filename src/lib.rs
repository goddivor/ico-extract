//! Extract icons from Windows PE files (`.dll` / `.exe`).
//!
//! Pure-Rust PE/`.rsrc` parser: it reads the `RT_GROUP_ICON` (id 14) and
//! `RT_ICON` (id 3) resources and reassembles a standard `.ico` file. No OS API
//! is involved, so it works on any platform and compiles to WebAssembly.

const RT_ICON: u32 = 3;
const RT_GROUP_ICON: u32 = 14;

// ---- little-endian readers (bounds-checked) --------------------------------

fn u16_at(b: &[u8], o: usize) -> Result<u16, String> {
    b.get(o..o + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
        .ok_or_else(|| format!("read u16 out of bounds at {o}"))
}

fn u32_at(b: &[u8], o: usize) -> Result<u32, String> {
    b.get(o..o + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        .ok_or_else(|| format!("read u32 out of bounds at {o}"))
}

// ---- PE sections -----------------------------------------------------------

struct Section {
    virtual_address: u32,
    virtual_size: u32,
    raw_ptr: u32,
    raw_size: u32,
}

struct Pe<'a> {
    bytes: &'a [u8],
    sections: Vec<Section>,
    resource_rva: u32,
}

impl<'a> Pe<'a> {
    fn parse(bytes: &'a [u8]) -> Result<Pe<'a>, String> {
        // DOS header -> e_lfanew (offset to PE header) at 0x3C.
        if bytes.len() < 0x40 || &bytes[0..2] != b"MZ" {
            return Err("not a PE file (missing MZ header)".into());
        }
        let pe_off = u32_at(bytes, 0x3C)? as usize;
        if bytes.get(pe_off..pe_off + 4) != Some(b"PE\0\0") {
            return Err("not a PE file (missing PE signature)".into());
        }

        // COFF header (20 bytes) right after the PE signature.
        let coff = pe_off + 4;
        let num_sections = u16_at(bytes, coff + 2)? as usize;
        let opt_size = u16_at(bytes, coff + 16)? as usize;
        let opt_off = coff + 20;

        // Optional header magic: 0x10b = PE32, 0x20b = PE32+.
        let magic = u16_at(bytes, opt_off)?;
        let data_dir_off = match magic {
            0x10b => opt_off + 96,
            0x20b => opt_off + 112,
            other => return Err(format!("unknown optional header magic {other:#x}")),
        };

        // Data directory index 2 = Resource Table (RVA, Size).
        let resource_rva = u32_at(bytes, data_dir_off + 2 * 8)?;

        // Section headers (40 bytes each) follow the optional header.
        let sec_off = opt_off + opt_size;
        let mut sections = Vec::with_capacity(num_sections);
        for i in 0..num_sections {
            let s = sec_off + i * 40;
            sections.push(Section {
                virtual_size: u32_at(bytes, s + 8)?,
                virtual_address: u32_at(bytes, s + 12)?,
                raw_size: u32_at(bytes, s + 16)?,
                raw_ptr: u32_at(bytes, s + 20)?,
            });
        }

        Ok(Pe { bytes, sections, resource_rva })
    }

    /// Convert a relative virtual address to a file offset.
    fn rva_to_offset(&self, rva: u32) -> Result<usize, String> {
        for s in &self.sections {
            let end = s.virtual_address + s.virtual_size.max(s.raw_size);
            if rva >= s.virtual_address && rva < end {
                return Ok((s.raw_ptr + (rva - s.virtual_address)) as usize);
            }
        }
        Err(format!("rva {rva:#x} not in any section"))
    }
}

// ---- resource directory traversal ------------------------------------------

const SUBDIR_FLAG: u32 = 0x8000_0000;

/// One entry of an IMAGE_RESOURCE_DIRECTORY: its id and either a subdirectory
/// offset or a leaf data-entry offset (both relative to the resource base).
struct ResEntry {
    id: u32,
    offset: u32,
    is_dir: bool,
}

fn read_dir_entries(b: &[u8], res_base: usize, dir_off: usize) -> Result<Vec<ResEntry>, String> {
    let base = res_base + dir_off;
    let named = u16_at(b, base + 12)? as usize;
    let ids = u16_at(b, base + 14)? as usize;
    let mut out = Vec::with_capacity(named + ids);
    for i in 0..(named + ids) {
        let e = base + 16 + i * 8;
        let name = u32_at(b, e)?;
        let off = u32_at(b, e + 4)?;
        out.push(ResEntry {
            id: name & 0x7fff_ffff,
            offset: off & 0x7fff_ffff,
            is_dir: off & SUBDIR_FLAG != 0,
        });
    }
    Ok(out)
}

/// Follow a leaf entry to its IMAGE_RESOURCE_DATA_ENTRY -> (data_rva, size).
fn read_data_entry(b: &[u8], res_base: usize, leaf_off: usize) -> Result<(u32, u32), String> {
    let p = res_base + leaf_off;
    Ok((u32_at(b, p)?, u32_at(b, p + 4)?))
}

/// Descend a (name -> language) subtree to the first language leaf's data.
fn first_leaf_data(pe: &Pe, res_base: usize, entry: &ResEntry) -> Result<Vec<u8>, String> {
    if !entry.is_dir {
        return Err("expected a subdirectory for the resource name level".into());
    }
    let langs = read_dir_entries(pe.bytes, res_base, entry.offset as usize)?;
    let lang = langs.first().ok_or("resource has no language entry")?;
    let (rva, size) = read_data_entry(pe.bytes, res_base, lang.offset as usize)?;
    let off = pe.rva_to_offset(rva)?;
    pe.bytes
        .get(off..off + size as usize)
        .map(|s| s.to_vec())
        .ok_or_else(|| "resource data out of bounds".into())
}

// ---- public API ------------------------------------------------------------

/// List the resource ids of every `RT_GROUP_ICON` in the file (in tree order).
pub fn list_icon_groups(pe_bytes: &[u8]) -> Result<Vec<u32>, String> {
    let pe = Pe::parse(pe_bytes)?;
    let res_base = pe.rva_to_offset(pe.resource_rva)?;
    let types = read_dir_entries(pe.bytes, res_base, 0)?;
    let group_type = match types.iter().find(|e| e.id == RT_GROUP_ICON) {
        Some(t) => t,
        None => return Ok(Vec::new()),
    };
    let names = read_dir_entries(pe.bytes, res_base, group_type.offset as usize)?;
    Ok(names.iter().map(|e| e.id).collect())
}

/// Build the `.ico` for one resolved RT_GROUP_ICON entry.
fn build_ico_for_group(
    pe: &Pe,
    res_base: usize,
    icon_names: &[ResEntry],
    group: &ResEntry,
) -> Result<Vec<u8>, String> {
    let group_data = first_leaf_data(pe, res_base, group)?;
    let images = collect_group_images(pe, res_base, icon_names, &group_data)?;
    Ok(build_ico(&images))
}

/// Read (RT_ICON names, RT_GROUP_ICON groups) directories from a parsed PE.
fn icon_dirs<'p>(pe: &'p Pe, res_base: usize) -> Result<(Vec<ResEntry>, Vec<ResEntry>), String> {
    let _ = pe; // keep signature symmetric
    let types = read_dir_entries(pe.bytes, res_base, 0)?;
    let icon_type = types
        .iter()
        .find(|e| e.id == RT_ICON)
        .ok_or("no RT_ICON resources in file")?;
    let group_type = types
        .iter()
        .find(|e| e.id == RT_GROUP_ICON)
        .ok_or("no RT_GROUP_ICON resources in file")?;
    let icon_names = read_dir_entries(pe.bytes, res_base, icon_type.offset as usize)?;
    let groups = read_dir_entries(pe.bytes, res_base, group_type.offset as usize)?;
    Ok((icon_names, groups))
}

/// Extract the icon group at `group_index` (0-based, tree order) as a `.ico`.
pub fn extract_icon(pe_bytes: &[u8], group_index: usize) -> Result<Vec<u8>, String> {
    let pe = Pe::parse(pe_bytes)?;
    let res_base = pe.rva_to_offset(pe.resource_rva)?;
    let (icon_names, groups) = icon_dirs(&pe, res_base)?;
    let group = groups
        .get(group_index)
        .ok_or_else(|| format!("group index {group_index} out of range ({} groups)", groups.len()))?;
    build_ico_for_group(&pe, res_base, &icon_names, group)
}

/// Extract the icon group whose Windows resource id is `id` as a `.ico`.
pub fn extract_icon_by_id(pe_bytes: &[u8], id: u32) -> Result<Vec<u8>, String> {
    let pe = Pe::parse(pe_bytes)?;
    let res_base = pe.rva_to_offset(pe.resource_rva)?;
    let (icon_names, groups) = icon_dirs(&pe, res_base)?;
    let group = groups
        .iter()
        .find(|g| g.id == id)
        .ok_or_else(|| format!("no icon group with id {id}"))?;
    build_ico_for_group(&pe, res_base, &icon_names, group)
}

/// For each entry of a GRPICONDIR, fetch the matching RT_ICON image bytes,
/// returning (grp_entry_14_bytes, image_bytes) pairs.
fn collect_group_images(
    pe: &Pe,
    res_base: usize,
    icon_names: &[ResEntry],
    group_data: &[u8],
) -> Result<Vec<([u8; 14], Vec<u8>)>, String> {
    let count = u16_at(group_data, 4)? as usize; // GRPICONDIR.idCount
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let e = 6 + i * 14; // GRPICONDIRENTRY is 14 bytes
        let raw: [u8; 14] = group_data
            .get(e..e + 14)
            .ok_or("group entry out of bounds")?
            .try_into()
            .unwrap();
        let icon_id = u16_at(group_data, e + 12)? as u32; // nID
        let name = icon_names
            .iter()
            .find(|n| n.id == icon_id)
            .ok_or_else(|| format!("RT_ICON id {icon_id} referenced by group not found"))?;
        let img = first_leaf_data(pe, res_base, name)?;
        out.push((raw, img));
    }
    Ok(out)
}

/// Assemble a `.ico` file from (GRPICONDIRENTRY, image) pairs.
fn build_ico(images: &[([u8; 14], Vec<u8>)]) -> Vec<u8> {
    let count = images.len() as u16;
    let mut out = Vec::new();

    // ICONDIR header
    out.extend_from_slice(&0u16.to_le_bytes()); // idReserved
    out.extend_from_slice(&1u16.to_le_bytes()); // idType = 1 (icon)
    out.extend_from_slice(&count.to_le_bytes()); // idCount

    // ICONDIRENTRY is 16 bytes; image data starts after all entries.
    let mut data_offset = 6 + 16 * images.len() as u32;

    for (grp, img) in images {
        // GRPICONDIRENTRY (14B): width,height,colors,reserved,planes(2),bits(2),
        // bytesInRes(4), nID(2). ICONDIRENTRY (16B) shares the first 12 bytes,
        // then a 4-byte image offset instead of the 2-byte id.
        out.extend_from_slice(&grp[0..12]); // through dwBytesInRes
        out.extend_from_slice(&data_offset.to_le_bytes());
        data_offset += img.len() as u32;
    }
    for (_, img) in images {
        out.extend_from_slice(img);
    }
    out
}

// ---- WASM binding (only with the `wasm` feature) ---------------------------

#[cfg(feature = "wasm")]
mod wasm {
    use wasm_bindgen::prelude::*;

    /// Extract the icon group at `group_index` as `.ico` bytes.
    #[wasm_bindgen(js_name = extractIcon)]
    pub fn extract_icon(pe_bytes: &[u8], group_index: usize) -> Result<Vec<u8>, JsValue> {
        super::extract_icon(pe_bytes, group_index).map_err(|e| JsValue::from_str(&e))
    }

    /// Extract the icon group whose Windows resource id is `id` as `.ico` bytes.
    #[wasm_bindgen(js_name = extractIconById)]
    pub fn extract_icon_by_id(pe_bytes: &[u8], id: u32) -> Result<Vec<u8>, JsValue> {
        super::extract_icon_by_id(pe_bytes, id).map_err(|e| JsValue::from_str(&e))
    }

    /// List the resource ids of every icon group in the file.
    #[wasm_bindgen(js_name = listIconGroups)]
    pub fn list_icon_groups(pe_bytes: &[u8]) -> Result<Vec<u32>, JsValue> {
        super::list_icon_groups(pe_bytes).map_err(|e| JsValue::from_str(&e))
    }
}

// ---- tests -----------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readers_bounds() {
        let b = [1u8, 0, 2, 0, 0, 0];
        assert_eq!(u16_at(&b, 0).unwrap(), 1);
        assert_eq!(u32_at(&b, 2).unwrap(), 2);
        assert!(u16_at(&b, 5).is_err());
        assert!(u32_at(&b, 4).is_err());
    }

    #[test]
    fn build_ico_layout() {
        // Two fake images of 3 and 5 bytes.
        let mut grp_a = [0u8; 14];
        grp_a[0] = 16; // width
        grp_a[1] = 16; // height
        let mut grp_b = [0u8; 14];
        grp_b[0] = 32;
        grp_b[1] = 32;
        let images = vec![(grp_a, vec![0xAA, 0xBB, 0xCC]), (grp_b, vec![1, 2, 3, 4, 5])];
        let ico = build_ico(&images);

        // Header
        assert_eq!(u16_at(&ico, 0).unwrap(), 0); // reserved
        assert_eq!(u16_at(&ico, 2).unwrap(), 1); // type icon
        assert_eq!(u16_at(&ico, 4).unwrap(), 2); // count

        // First entry width/height preserved, offset points past the directory.
        assert_eq!(ico[6], 16);
        assert_eq!(ico[7], 16);
        let off_a = u32_at(&ico, 6 + 12).unwrap() as usize;
        assert_eq!(off_a, 6 + 16 * 2); // after header + 2 entries
        assert_eq!(&ico[off_a..off_a + 3], &[0xAA, 0xBB, 0xCC]);

        // Second image right after the first.
        let off_b = u32_at(&ico, 6 + 16 + 12).unwrap() as usize;
        assert_eq!(off_b, off_a + 3);
        assert_eq!(&ico[off_b..off_b + 5], &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn rejects_non_pe() {
        assert!(extract_icon(b"not a pe file at all", 0).is_err());
        assert!(list_icon_groups(b"xx").is_err());
    }
}
