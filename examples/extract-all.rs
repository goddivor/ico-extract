//! Extract every icon group from a PE/MUN file into a directory, one `.ico`
//! per group named by its Windows resource id.
//!
//!   cargo run --example extract-all -- [-q|--quiet] <file> [out_dir]
//!
//! Default out_dir is "./icons". With -q/--quiet nothing is printed on success.

use std::env;
use std::fs;
use std::path::Path;

fn main() {
    let mut args: Vec<String> = env::args().skip(1).collect();
    let quiet = take_flag(&mut args, "-q", "--quiet");

    if args.is_empty() {
        eprintln!("usage: extract-all [-q|--quiet] <file> [out_dir]");
        std::process::exit(2);
    }
    let bytes = fs::read(&args[0]).expect("read input file");
    let out_dir = args.get(1).cloned().unwrap_or_else(|| "icons".to_string());
    fs::create_dir_all(&out_dir).expect("create out dir");

    let ids = ico_extract::list_icon_groups(&bytes).expect("list groups");
    if !quiet {
        println!("{} icon groups in {}", ids.len(), args[0]);
    }

    let mut ok = 0;
    let mut failed = 0;
    for id in &ids {
        match ico_extract::extract_icon_by_id(&bytes, *id) {
            Ok(ico) => {
                let path = Path::new(&out_dir).join(format!("{id}.ico"));
                fs::write(&path, &ico).expect("write ico");
                ok += 1;
            }
            Err(e) => {
                eprintln!("  id {id}: {e}");
                failed += 1;
            }
        }
    }
    if !quiet {
        println!("wrote {ok} .ico files to {}/ ({failed} failed)", out_dir);
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
