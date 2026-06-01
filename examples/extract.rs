//! Manual test harness: extract icons from a real PE file.
//!
//!   cargo run --example extract -- <file.dll> [group_index] [out.ico]

use std::env;
use std::fs;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: extract <file.dll> [group_index] [out.ico]");
        std::process::exit(2);
    }
    let bytes = fs::read(&args[1]).expect("read input file");
    println!("file: {} ({} bytes)", args[1], bytes.len());

    match ico_extract::list_icon_groups(&bytes) {
        Ok(groups) => {
            println!("icon groups: {} -> ids {:?}", groups.len(), groups);
            if groups.is_empty() {
                println!("(no RT_GROUP_ICON; resources may live in a .mun file)");
                return;
            }
        }
        Err(e) => {
            eprintln!("list_icon_groups error: {e}");
            std::process::exit(1);
        }
    }

    let index: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);
    match ico_extract::extract_icon(&bytes, index) {
        Ok(ico) => {
            let out = args.get(3).cloned().unwrap_or_else(|| "out.ico".to_string());
            fs::write(&out, &ico).expect("write ico");
            let ok = ico.len() >= 6 && ico[0] == 0 && ico[1] == 0 && ico[2] == 1 && ico[3] == 0;
            let count = u16::from_le_bytes([ico[4], ico[5]]);
            println!(
                "extracted group #{index}: {} bytes, {} images, valid ICO header: {} -> {}",
                ico.len(),
                count,
                ok,
                out
            );
        }
        Err(e) => {
            eprintln!("extract_icon error: {e}");
            std::process::exit(1);
        }
    }
}
