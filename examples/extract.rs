//! Manual test harness: extract icons from a real PE file.
//!
//!   cargo run --example extract -- [-q|--quiet] <file.dll> [group_index] [out.ico]
//!
//! With -q/--quiet, nothing is printed on success (only the .ico is written);
//! errors still go to stderr and set a non-zero exit code.

use std::env;
use std::fs;

fn main() {
    let mut args: Vec<String> = env::args().skip(1).collect();
    let quiet = take_flag(&mut args, "-q", "--quiet");

    if args.is_empty() {
        eprintln!("usage: extract [-q|--quiet] <file.dll> [group_index] [out.ico]");
        std::process::exit(2);
    }
    let bytes = fs::read(&args[0]).expect("read input file");
    if !quiet {
        println!("file: {} ({} bytes)", args[0], bytes.len());
    }

    match ico_extract::list_icon_groups(&bytes) {
        Ok(groups) => {
            if !quiet {
                println!("icon groups: {} -> ids {:?}", groups.len(), groups);
            }
            if groups.is_empty() {
                if !quiet {
                    println!("(no RT_GROUP_ICON; resources may live in a .mun file)");
                }
                return;
            }
        }
        Err(e) => {
            eprintln!("list_icon_groups error: {e}");
            std::process::exit(1);
        }
    }

    let index: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    match ico_extract::extract_icon(&bytes, index) {
        Ok(ico) => {
            let out = args.get(2).cloned().unwrap_or_else(|| "out.ico".to_string());
            fs::write(&out, &ico).expect("write ico");
            if !quiet {
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
        }
        Err(e) => {
            eprintln!("extract_icon error: {e}");
            std::process::exit(1);
        }
    }
}

/// Remove a boolean flag (short or long form) from args if present.
fn take_flag(args: &mut Vec<String>, short: &str, long: &str) -> bool {
    if let Some(i) = args.iter().position(|a| a == short || a == long) {
        args.remove(i);
        true
    } else {
        false
    }
}
