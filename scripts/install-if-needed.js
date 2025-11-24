const fs = require('fs');
const path = require('path');
const cp = require('child_process');

const indexPath = path.join(__dirname, '..', 'index.node');
if (fs.existsSync(indexPath)) {
  console.log('install-if-needed: prebuilt native found, skipping build.');
  process.exit(0);
}

console.log('install-if-needed: no prebuilt native found, running build-native.js');
const r = cp.spawnSync(process.execPath, [require.resolve('./build-native.js')], { stdio: 'inherit' });
process.exit(r.status === null ? 1 : r.status);
