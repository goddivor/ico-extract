<div align="center">

# ico-extract

Extract icons (`.ico`) from Windows PE files (`.dll` / `.exe`).

</div>

A small, dependency-free **Rust** PE parser that reads the `RT_GROUP_ICON` /
`RT_ICON` resources of a Windows executable and reassembles a standard `.ico`
file. It does **not** call any OS API — it just parses the file format — so it
runs on **any platform** and compiles to **WebAssembly** for use from Node.js.

Typical use: pull the native folder icon out of `imageres.dll` /
`shell32.dll`, no Windows tooling (Resource Hacker, PowerShell) required.

> **Windows 10/11 note:** stock icons are no longer stored in the `.dll`
> itself but in a matching `.mun` file under
> `C:\Windows\SystemResources\` (e.g. `imageres.dll.mun`). A `.mun` is a
> regular PE, so point the extractor at it. For example, the generic folder
> icon is resource id **4** in `imageres.dll.mun`.

## Why

Windows embeds its stock icons inside DLLs as PE resources. Reading them is pure
byte parsing of a documented format (PE → `.rsrc` directory tree → icon
groups), not an OS feature — so it can be done portably and shipped as a single
`.wasm` artifact on npm.

## Install

```bash
npm i ico-extract
```

## Usage (Node.js)

```js
import { extractIcon, listIconGroups } from 'ico-extract';
import fs from 'fs';

const pe = fs.readFileSync('C:\\Windows\\System32\\imageres.dll');

// List the resource ids of every icon group in the file.
const groups = listIconGroups(pe);

// Extract the first icon group as a multi-size .ico.
const ico = extractIcon(pe, 0);
fs.writeFileSync('folder.ico', ico);
```

> Node reads the file and passes the bytes; the WASM module never touches the
> disk. This works even when the `.dll` comes from another machine.

## API

| Function | Signature | Returns |
| -------- | --------- | ------- |
| `listIconGroups(peBytes)` | `(Uint8Array) => Uint32Array` | resource ids of each `RT_GROUP_ICON` (tree order) |
| `extractIcon(peBytes, groupIndex)` | `(Uint8Array, number) => Uint8Array` | `.ico` bytes for the group at `groupIndex` (0-based) |
| `extractIconById(peBytes, id)` | `(Uint8Array, number) => Uint8Array` | `.ico` bytes for the group whose Windows resource id is `id` |

## Build from source

Requires the Rust toolchain and [`wasm-pack`](https://rustwasm.github.io/wasm-pack/).

```bash
# native tests (no wasm needed)
cargo test

# build the npm/WASM package into pkg/
rustup target add wasm32-unknown-unknown
cargo install wasm-pack
npm run build        # -> pkg/  (publish that directory)
```

The native library has **zero dependencies**; `wasm-bindgen` is pulled in only
for the optional `wasm` feature used by `wasm-pack`.

## Scope

- ✅ Read / extract icon groups from PE files.
- ❌ Writing or replacing resources (a full Resource-Hacker clone) is out of scope.

## License

MIT
