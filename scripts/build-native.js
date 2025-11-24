
'use strict';

const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '..');
const rustDir = path.join(root, 'rust');

function runCargo() {
  return new Promise((resolve, reject) => {
    const cargo = spawn('cargo', ['build', '--release'], { cwd: rustDir, stdio: 'inherit' });
    cargo.on('close', (code) => {
      if (code === 0) resolve(); else reject(new Error('cargo build failed with code ' + code));
    });
  });
}

function findLibrary() {
  const targetDir = path.join(rustDir, 'target', 'release');
  if (!fs.existsSync(targetDir)) return null;
  const files = fs.readdirSync(targetDir);
  // Preferred output names / extensions
  const candExt = process.platform === 'win32' ? ['dll'] : (process.platform === 'darwin' ? ['dylib'] : ['so']);
  for (const f of files) {
    for (const ext of candExt) {
      if (f.endsWith('.' + ext)) {
        return path.join(targetDir, f);
      }
    }
  }
  // fallback: find any .so/.dylib/.dll
  for (const f of files) {
    if (f.endsWith('.so') || f.endsWith('.dylib') || f.endsWith('.dll')) return path.join(targetDir, f);
  }
  return null;
}

async function main() {
  try {
    console.log('Building Rust crate (release) in', rustDir);
    await runCargo();

    const lib = findLibrary();
    if (!lib) {
      console.error('Could not find compiled native library in target/release');
      process.exit(1);
    }
    console.log('Found native library:', lib);

    const dest = path.join(root, 'index.node');
    fs.copyFileSync(lib, dest);
    try { fs.chmodSync(dest, 0o755); } catch (e) {}
    console.log('Copied native library to', dest);
  } catch (err) {
    console.error('build-native failed:', err);
    process.exit(1);
  }
}

main();
