# libsignal-rs

Rust native bindings for libsignal primitives exposed via N-API.

Usage

- Build locally: `npm run build-native` (requires Rust toolchain and cargo)
```bash
$ npm run build-native
```
if you want to override [Baileys](https://github.com/whiskeysockeys/Baileys) libsignal
you can easily add following to your `package.json`:
```json
"overrides": {
  "libsignal": "github:pluvism/libsignal-rs"
}
```
and then reinstall the `node_modules`
