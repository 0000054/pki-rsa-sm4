const test = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const { once } = require('node:events');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');

test('fresh startup, certificate lifecycle, signatures and SM4 round trip', { timeout: 45000 }, async (t) => {
  const dataDir = await fs.mkdtemp(path.join(os.tmpdir(), 'pki-test-'));
  const child = spawn(process.execPath, ['src/server.js'], {
    cwd: path.join(__dirname, '..'),
    env: { ...process.env, PORT: '0', PKI_DATA_DIR: dataDir },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  let errors = '';
  child.stderr.on('data', (chunk) => { errors += chunk; });
  t.after(async () => {
    if (child.exitCode === null && child.signalCode === null) {
      const exited = once(child, 'exit');
      child.kill();
      await exited;
    }
    await fs.rm(dataDir, { recursive: true, force: true });
  });
  const base = await new Promise((resolve, reject) => {
    let output = '';
    child.stdout.on('data', (chunk) => {
      output += chunk;
      const match = output.match(/http:\/\/127\.0\.0\.1:\d+/);
      if (match) resolve(match[0]);
    });
    child.once('error', reject);
    child.once('exit', (code) => reject(new Error(`Server exited (${code}): ${errors}`)));
  });
  async function api(route, body) {
    const response = await fetch(base + route, body === undefined ? {} : {
      method: 'POST',
      headers: body instanceof FormData ? {} : { 'Content-Type': 'application/json' },
      body: body instanceof FormData ? body : JSON.stringify(body)
    });
    assert.equal(response.ok, true, `${route}: ${response.status}`);
    return response.json();
  }
  function fileForm(fields, content = 'PKI demo test') {
    const form = new FormData();
    for (const [key, value] of Object.entries(fields)) form.append(key, value);
    form.append('file', new Blob([content]), 'sample.txt');
    return form;
  }
  const overview = await api('/api/overview');
  assert.equal(overview.counts.issued, 0);
  assert.match(overview.caCertificatePem, /BEGIN CERTIFICATE/);
  const request = await api('/api/requests', { commonName: 'alice.pki.test', organization: 'Demo' });
  const cert = await api(`/api/requests/${request.id}/approve`, {});
  assert.equal(cert.status, 'active');
  assert.equal(cert.privateKeyPem, undefined);
  const signed = await api('/api/sign', fileForm({ certificateId: cert.id }));
  const verified = await api('/api/verify', fileForm({ certificateId: cert.id, signature: signed.signature }));
  assert.equal(verified.valid, true);
  const tampered = await api('/api/verify', fileForm({ certificateId: cert.id, signature: signed.signature }, 'changed'));
  assert.equal(tampered.valid, false);
  const encrypted = await api('/api/sm4/encrypt', fileForm({}));
  const decrypted = await api('/api/sm4/decrypt', { encryptedHex: encrypted.encryptedHex, keyHex: encrypted.keyHex });
  assert.equal(decrypted.plainTextPreview, 'PKI demo test');
  assert.equal(decrypted.plainHash, encrypted.originalHash);
  await api(`/api/certificates/${cert.id}/revoke`, { reason: 'keyCompromise' });
  const revoked = await api('/api/verify', fileForm({ certificateId: cert.id, signature: signed.signature }));
  assert.equal(revoked.valid, false);
  const crl = await api('/api/crl');
  assert.equal(crl.revokedCertificates.length, 1);
  assert.equal(errors, '');
});
