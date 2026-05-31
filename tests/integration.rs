//! End-to-end test against a hand-built minimal PE that embeds one icon.
//!
//! Building a tiny valid-enough PE in-memory lets us exercise the real parser
//! (PE headers -> .rsrc tree -> RT_GROUP_ICON/RT_ICON -> .ico) without shipping
//! a binary fixture or needing Windows.

use ico_extract::{extract_icon, list_icon_groups};

fn le16(v: u16) -> [u8; 2] {
    v.to_le_bytes()
}
fn le32(v: u32) -> [u8; 4] {
    v.to_le_bytes()
}

/// Build a minimal PE32 with a single .rsrc section holding one RT_ICON and one
/// RT_GROUP_ICON that references it. Layout is kept simple: one section, the
/// resource RVA equals its file offset so rva_to_offset is identity-ish.
fn build_pe_with_icon(icon_image: &[u8]) -> Vec<u8> {
    // --- resource section content (built first, then placed) ---
    // We lay out, inside .rsrc (base = 0):
    //   [type dir][icon-name dir][icon-lang dir]
    //   [group-name dir][group-lang dir]
    //   [data entries] [GRPICONDIR bytes] [icon image bytes]
    // All "offset" fields in directories are relative to the resource base.

    // Reserve fixed offsets by constructing sequentially.
    let dir_hdr = 16usize; // IMAGE_RESOURCE_DIRECTORY header size
    let entry = 8usize; // IMAGE_RESOURCE_DIRECTORY_ENTRY size

    // Offsets within .rsrc:
    let type_dir = 0usize; // root: 2 types (RT_ICON=3, RT_GROUP_ICON=14)
    let icon_name_dir = type_dir + dir_hdr + 2 * entry; // after root + 2 entries
    let icon_lang_dir = icon_name_dir + dir_hdr + entry;
    let group_name_dir = icon_lang_dir + dir_hdr + entry;
    let group_lang_dir = group_name_dir + dir_hdr + entry;
    let icon_data_entry = group_lang_dir + dir_hdr + entry; // 16 bytes
    let group_data_entry = icon_data_entry + 16;
    let grpicondir = group_data_entry + 16;
    // GRPICONDIR = 6 + 14 (one entry)
    let icon_image_off = grpicondir + 6 + 14;

    let mut r = vec![0u8; icon_image_off + icon_image.len()];

    // helper closures to write
    let write = |r: &mut Vec<u8>, at: usize, bytes: &[u8]| {
        r[at..at + bytes.len()].copy_from_slice(bytes);
    };

    // root type directory: 0 named, 2 id entries
    write(&mut r, type_dir + 12, &le16(0));
    write(&mut r, type_dir + 14, &le16(2));
    // entry 0: RT_ICON (3) -> icon_name_dir (subdir)
    let e0 = type_dir + dir_hdr;
    write(&mut r, e0, &le32(3));
    write(&mut r, e0 + 4, &le32(icon_name_dir as u32 | 0x8000_0000));
    // entry 1: RT_GROUP_ICON (14) -> group_name_dir (subdir)
    let e1 = e0 + entry;
    write(&mut r, e1, &le32(14));
    write(&mut r, e1 + 4, &le32(group_name_dir as u32 | 0x8000_0000));

    // icon name dir: 1 id entry, id=1 -> icon_lang_dir
    write(&mut r, icon_name_dir + 14, &le16(1));
    let ie = icon_name_dir + dir_hdr;
    write(&mut r, ie, &le32(1));
    write(&mut r, ie + 4, &le32(icon_lang_dir as u32 | 0x8000_0000));
    // icon lang dir: 1 id entry, lang -> icon_data_entry (leaf)
    write(&mut r, icon_lang_dir + 14, &le16(1));
    let ile = icon_lang_dir + dir_hdr;
    write(&mut r, ile, &le32(0x0409));
    write(&mut r, ile + 4, &le32(icon_data_entry as u32)); // leaf (no high bit)

    // group name dir: 1 id entry, id=1 -> group_lang_dir
    write(&mut r, group_name_dir + 14, &le16(1));
    let ge = group_name_dir + dir_hdr;
    write(&mut r, ge, &le32(1));
    write(&mut r, ge + 4, &le32(group_lang_dir as u32 | 0x8000_0000));
    // group lang dir: 1 id entry -> group_data_entry (leaf)
    write(&mut r, group_lang_dir + 14, &le16(1));
    let gle = group_lang_dir + dir_hdr;
    write(&mut r, gle, &le32(0x0409));
    write(&mut r, gle + 4, &le32(group_data_entry as u32));

    // data entries hold an RVA; we set RVA == offset (single section starts at 0 rva-wise below)
    // icon data entry -> points at icon_image_off, size = image len
    write(&mut r, icon_data_entry, &le32(icon_image_off as u32));
    write(&mut r, icon_data_entry + 4, &le32(icon_image.len() as u32));
    // group data entry -> points at grpicondir, size = 6 + 14
    write(&mut r, group_data_entry, &le32(grpicondir as u32));
    write(&mut r, group_data_entry + 4, &le32((6 + 14) as u32));

    // GRPICONDIR: reserved(0), type(1), count(1)
    write(&mut r, grpicondir + 0, &le16(0));
    write(&mut r, grpicondir + 2, &le16(1));
    write(&mut r, grpicondir + 4, &le16(1));
    // GRPICONDIRENTRY (14): width,height,colors,res,planes,bits,bytesInRes(4),id(2)
    let gde = grpicondir + 6;
    r[gde] = 32; // width
    r[gde + 1] = 32; // height
    write(&mut r, gde + 8, &le32(icon_image.len() as u32)); // bytesInRes
    write(&mut r, gde + 12, &le16(1)); // nID -> RT_ICON id 1

    // the icon image itself
    write(&mut r, icon_image_off, icon_image);

    // --- now wrap r as the .rsrc section of a minimal PE ---
    // Choose a file layout: [headers padded to 0x200][.rsrc raw]
    let headers_size = 0x200usize;
    let rsrc_rva = 0x1000u32;
    let rsrc_raw_ptr = headers_size as u32;

    let mut pe = vec![0u8; headers_size + r.len()];

    // DOS header: 'MZ' + e_lfanew at 0x3C
    pe[0] = b'M';
    pe[1] = b'Z';
    let pe_off = 0x80u32;
    pe[0x3C..0x40].copy_from_slice(&le32(pe_off));

    // PE signature
    let p = pe_off as usize;
    pe[p..p + 4].copy_from_slice(b"PE\0\0");
    // COFF header
    let coff = p + 4;
    pe[coff + 2..coff + 4].copy_from_slice(&le16(1)); // NumberOfSections = 1
    let opt_size: u16 = 0xE0; // typical PE32 optional header size
    pe[coff + 16..coff + 18].copy_from_slice(&le16(opt_size));
    // Optional header
    let opt = coff + 20;
    pe[opt..opt + 2].copy_from_slice(&le16(0x10b)); // PE32 magic
    // Data directory index 2 (Resource) at opt + 96
    let dd = opt + 96;
    pe[dd + 2 * 8..dd + 2 * 8 + 4].copy_from_slice(&le32(rsrc_rva));
    pe[dd + 2 * 8 + 4..dd + 2 * 8 + 8].copy_from_slice(&le32(r.len() as u32));

    // Section header (40 bytes) after optional header
    let sec = opt + opt_size as usize;
    pe[sec..sec + 5].copy_from_slice(b".rsrc");
    pe[sec + 8..sec + 12].copy_from_slice(&le32(r.len() as u32)); // VirtualSize
    pe[sec + 12..sec + 16].copy_from_slice(&le32(rsrc_rva)); // VirtualAddress
    pe[sec + 16..sec + 20].copy_from_slice(&le32(r.len() as u32)); // SizeOfRawData
    pe[sec + 20..sec + 24].copy_from_slice(&le32(rsrc_raw_ptr)); // PointerToRawData

    // But our resource offsets above were relative to base 0 while data entries
    // store RVAs; rva_to_offset maps rva -> raw_ptr + (rva - va). Our data
    // entry RVAs were written as plain offsets, so shift them by rsrc_rva.
    // Easiest: place .rsrc so that rva == offset, i.e. fix the data-entry RVAs.
    // Re-point the two data entries to RVA = rsrc_rva + offset.
    let fix = |buf: &mut [u8], at: usize, base: u32| {
        let cur = u32::from_le_bytes([buf[at], buf[at + 1], buf[at + 2], buf[at + 3]]);
        buf[at..at + 4].copy_from_slice(&(cur + base).to_le_bytes());
    };
    fix(&mut r, icon_data_entry, rsrc_rva);
    fix(&mut r, group_data_entry, rsrc_rva);

    // copy resource bytes into the section
    pe[rsrc_raw_ptr as usize..rsrc_raw_ptr as usize + r.len()].copy_from_slice(&r);

    pe
}

#[test]
fn extracts_single_icon_to_ico() {
    let image = [0xDEu8, 0xAD, 0xBE, 0xEF, 0x11, 0x22]; // fake image payload
    let pe = build_pe_with_icon(&image);

    let groups = list_icon_groups(&pe).expect("list groups");
    assert_eq!(groups, vec![1], "one group with id 1");

    let ico = extract_icon(&pe, 0).expect("extract");
    // ICONDIR header: reserved=0, type=1, count=1
    assert_eq!(&ico[0..2], &[0, 0]);
    assert_eq!(u16::from_le_bytes([ico[2], ico[3]]), 1);
    assert_eq!(u16::from_le_bytes([ico[4], ico[5]]), 1);
    // width/height carried over from the group entry
    assert_eq!(ico[6], 32);
    assert_eq!(ico[7], 32);
    // the image bytes are appended after the 6 + 16 directory
    let off = u32::from_le_bytes([ico[18], ico[19], ico[20], ico[21]]) as usize;
    assert_eq!(off, 6 + 16);
    assert_eq!(&ico[off..off + image.len()], &image);
}

#[test]
fn out_of_range_group_errors() {
    let pe = build_pe_with_icon(&[1, 2, 3]);
    assert!(extract_icon(&pe, 5).is_err());
}
