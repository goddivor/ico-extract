//! Extract every icon group from a PE/MUN file into a directory, one `.ico`
//! per group named by its Windows resource id.
//!
//!   cargo run --example extract-all -- <file> [out_dir]
//!
//! Default out_dir is "./icons".

use std::env;
use std::fs;
use std::path::Path;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: extract-all <file> [out_dir]");
        std::process::exit(2);
    }
    let bytes = fs::read(&args[1]).expect("read input file");
    let out_dir = args.get(2).cloned().unwrap_or_else(|| "icons".to_string());
    fs::create_dir_all(&out_dir).expect("create out dir");

    let ids = ico_extract::list_icon_groups(&bytes).expect("list groups");
    println!("{} icon groups in {}", ids.len(), args[1]);

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
    println!("wrote {ok} .ico files to {}/ ({failed} failed)", out_dir);
}
