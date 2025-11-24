const https = require('https');
const fs = require('fs');
const path = require('path');

const repo = process.env.LIBSIGNAL_RS_RELEASE_REPO || 'pluvism/libsignal-rs';
const token = process.env.GITHUB_TOKEN || process.env.LIBSIGNAL_RS_GITHUB_TOKEN || null;

function getAssetName() {
  const plat = process.platform;
  const arch = process.arch;

  
  if (plat === 'android') {
    if (arch === 'arm64' || arch === 'aarch64') return 'libsignal-rs-android-arm64.node';
    if (arch === 'arm' || arch === 'armv7l') return 'libsignal-rs-android-armv7.node';
  }
  
  if (plat === 'linux') {
    if (arch === 'x64') return 'libsignal-rs-linux-x86_64.node';
    if (arch === 'arm64' || arch === 'aarch64') {
      
      if (process.env.ANDROID_ROOT || process.env.ANDROID_DATA) return 'libsignal-rs-android-arm64.node';
      return 'libsignal-rs-linux-aarch64.node';
    }
    if (arch === 'arm' || arch === 'armv7l') {
      if (process.env.ANDROID_ROOT || process.env.ANDROID_DATA) return 'libsignal-rs-android-armv7.node';
      return 'libsignal-rs-linux-armv7.node'; 
    }
  }
  if (plat === 'darwin') return 'libsignal-rs-macos.node';
  if (plat === 'win32') return 'libsignal-rs-windows.dll';

  return null;
}

function getJSON(url) {
  return new Promise((resolve, reject) => {
    const opts = { headers: { 'User-Agent': 'libsignal-rs-Postinstall' } };
    if (token) opts.headers['Authorization'] = `token ${token}`;
    https.get(url, opts, (res) => {
      let data = '';
      res.on('data', (c) => (data += c));
      res.on('end', () => {
        if (res.statusCode >= 400) return reject(new Error('Failed to fetch ' + url + ' status=' + res.statusCode));
        try {
          resolve(JSON.parse(data));
        } catch (e) {
          reject(e);
        }
      });
    }).on('error', reject);
  });
}

function download(url, dest) {
  return new Promise((resolve, reject) => {
    const file = fs.createWriteStream(dest);
    const opts = { headers: { 'User-Agent': 'libsignal-rs-postinstall' } };
    if (token) opts.headers['Authorization'] = `token ${token}`;
    https.get(url, opts, (res) => {
      
      if (res.statusCode === 302 || res.statusCode === 301) {
        return download(res.headers.location, dest).then(resolve).catch(reject);
      }
      if (res.statusCode >= 400) return reject(new Error('Download failed: ' + res.statusCode));
      res.pipe(file);
      file.on('finish', () => {
        file.close(() => resolve());
      });
    }).on('error', (err) => {
      try { fs.unlinkSync(dest); } catch (e) {}
      reject(err);
    });
  });
}

(async function main() {
  try {
    const assetName = getAssetName();
    const outPath = path.join(__dirname, '..', 'index.node');

    if (!assetName) {
      console.log('Postinstall: no prebuilt available for this platform/arch; skipping download.');
      return process.exit(0);
    }

    
    if (fs.existsSync(outPath)) {
      console.log('Postinstall: native binary already present, skipping download.');
      return process.exit(0);
    }

    console.log(`Postinstall: looking for release asset '${assetName}' in ${repo}`);
    const apiUrl = `https://api.github.com/repos/${repo}/releases/latest`;
    const release = await getJSON(apiUrl);
    if (!release || !Array.isArray(release.assets)) {
      console.log('Postinstall: no release assets found, falling back to build.');
      return process.exit(0);
    }

    const asset = release.assets.find(a => a.name === assetName);
    if (!asset) {
      console.log(`Postinstall: asset '${assetName}' not found in latest release; falling back to build.`);
      return process.exit(0);
    }

    console.log(`Postinstall: downloading ${asset.browser_download_url} ...`);
    await download(asset.browser_download_url, outPath);
    console.log('Postinstall: downloaded native asset to', outPath);
    
    try { fs.chmodSync(outPath, 0o755); } catch (e) {}
    process.exit(0);
  } catch (err) {
    console.error('Postinstall: error while attempting to download prebuilt:', err.message || err);
    console.log('Postinstall: continuing install; build-from-source will be attempted if available.');
    return process.exit(0);
  }
})();
