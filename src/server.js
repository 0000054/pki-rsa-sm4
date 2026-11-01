const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const express = require("express");
const multer = require("multer");
const forge = require("node-forge");
const { sm4 } = require("sm-crypto");

const app = express();
const PORT = process.env.PORT || 3000;

const ROOT = path.join(__dirname, "..");
const DATA_DIR = process.env.PKI_DATA_DIR || path.join(ROOT, "data");
const STORE_FILE = path.join(DATA_DIR, "store.json");
const CA_KEY_FILE = path.join(DATA_DIR, "ca-private.pem");
const CA_CERT_FILE = path.join(DATA_DIR, "ca-certificate.pem");

function ensureDataDir() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

function createInitialStore() {
  return {
    requests: [],
    certificates: [],
    auditLogs: [],
    sm4KeyHex: crypto.randomBytes(16).toString("hex")
  };
}

ensureDataDir();

app.use(express.json({ limit: "5mb" }));
app.use(express.static(path.join(ROOT, "public")));

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 }
});

function loadStore() {
  ensureDataDir();

  try {
    if (!fs.existsSync(STORE_FILE)) {
      const initialStore = createInitialStore();
      saveStore(initialStore);
      return initialStore;
    }

    return JSON.parse(fs.readFileSync(STORE_FILE, "utf8"));
  } catch (error) {
    if (error.code !== "ENOENT" && error.name !== "SyntaxError") {
      throw error;
    }

    const initialStore = createInitialStore();
    saveStore(initialStore);
    return initialStore;
  }
}

function saveStore(store) {
  ensureDataDir();
  fs.writeFileSync(STORE_FILE, JSON.stringify(store, null, 2));
}

function addAudit(store, action, detail) {
  store.auditLogs.unshift({
    id: crypto.randomUUID(),
    action,
    detail,
    at: new Date().toISOString()
  });
}

function getCaMaterial() {
  ensureDataDir();

  if (fs.existsSync(CA_KEY_FILE) && fs.existsSync(CA_CERT_FILE)) {
    return {
      keyPem: fs.readFileSync(CA_KEY_FILE, "utf8"),
      certPem: fs.readFileSync(CA_CERT_FILE, "utf8")
    };
  }

  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = createSerialNumber();
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 10);

  const attrs = [
    { name: "commonName", value: "Mini PKI Demo Root CA" },
    { name: "organizationName", value: "Crypto Engineering Course" },
    { name: "countryName", value: "CN" }
  ];

  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.setExtensions([
    { name: "basicConstraints", cA: true, critical: true },
    { name: "keyUsage", keyCertSign: true, cRLSign: true, critical: true },
    { name: "subjectKeyIdentifier" }
  ]);
  cert.sign(keys.privateKey, forge.md.sha256.create());

  const keyPem = forge.pki.privateKeyToPem(keys.privateKey);
  const certPem = forge.pki.certificateToPem(cert);
  fs.writeFileSync(CA_KEY_FILE, keyPem);
  fs.writeFileSync(CA_CERT_FILE, certPem);
  return { keyPem, certPem };
}

function createSerialNumber() {
  return crypto.randomBytes(16).toString("hex");
}

function certFingerprint(certPem) {
  const der = forge.asn1.toDer(forge.pki.certificateToAsn1(forge.pki.certificateFromPem(certPem))).getBytes();
  return crypto.createHash("sha256").update(Buffer.from(der, "binary")).digest("hex").toUpperCase();
}

function issueCertificate(commonName, organization, email) {
  const ca = getCaMaterial();
  const caKey = forge.pki.privateKeyFromPem(ca.keyPem);
  const caCert = forge.pki.certificateFromPem(ca.certPem);
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();

  cert.publicKey = keys.publicKey;
  cert.serialNumber = createSerialNumber();
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);

  const subject = [
    { name: "commonName", value: commonName },
    { name: "organizationName", value: organization || "PKI Lab User" },
    { name: "countryName", value: "CN" }
  ];

  if (email) {
    subject.push({ name: "emailAddress", value: email });
  }

  cert.setSubject(subject);
  cert.setIssuer(caCert.subject.attributes);
  cert.setExtensions([
    { name: "basicConstraints", cA: false },
    { name: "keyUsage", digitalSignature: true, keyEncipherment: true },
    { name: "extKeyUsage", clientAuth: true, emailProtection: true },
    { name: "subjectKeyIdentifier" }
  ]);
  cert.sign(caKey, forge.md.sha256.create());

  const certificatePem = forge.pki.certificateToPem(cert);
  return {
    serialNumber: cert.serialNumber,
    certificatePem,
    privateKeyPem: forge.pki.privateKeyToPem(keys.privateKey),
    publicKeyPem: forge.pki.publicKeyToPem(keys.publicKey),
    validFrom: cert.validity.notBefore.toISOString(),
    validTo: cert.validity.notAfter.toISOString(),
    fingerprint: certFingerprint(certificatePem)
  };
}

function findActiveCertificate(store, certificateId) {
  const cert = store.certificates.find((item) => item.id === certificateId);
  if (!cert) {
    const error = new Error("证书不存在");
    error.status = 404;
    throw error;
  }

  if (cert.status === "revoked") {
    const error = new Error("证书已吊销");
    error.status = 400;
    throw error;
  }

  return cert;
}

function verifyCertificateIssuedByCa(certificatePem) {
  const ca = getCaMaterial();
  const caCert = forge.pki.certificateFromPem(ca.certPem);
  const cert = forge.pki.certificateFromPem(certificatePem);
  return caCert.verify(cert);
}

function asHexSm4Key(value) {
  const trimmed = String(value || "").trim();
  if (!/^[0-9a-fA-F]{32}$/.test(trimmed)) {
    const error = new Error("SM4 密钥必须是 32 位十六进制字符串");
    error.status = 400;
    throw error;
  }
  return trimmed.toLowerCase();
}

app.get("/api/overview", (req, res) => {
  const store = loadStore();
  const ca = getCaMaterial();
  res.json({
    caCertificatePem: ca.certPem,
    sm4KeyHex: store.sm4KeyHex,
    counts: {
      pending: store.requests.filter((item) => item.status === "pending").length,
      issued: store.certificates.filter((item) => item.status === "active").length,
      revoked: store.certificates.filter((item) => item.status === "revoked").length
    },
    requests: store.requests,
    certificates: store.certificates.map(({ privateKeyPem, ...item }) => item),
    auditLogs: store.auditLogs.slice(0, 20)
  });
});

app.post("/api/requests", (req, res) => {
  const { commonName, organization, email } = req.body;
  if (!commonName || commonName.trim().length < 2) {
    return res.status(400).json({ message: "证书主体名称至少需要 2 个字符" });
  }

  const store = loadStore();
  const request = {
    id: crypto.randomUUID(),
    commonName: commonName.trim(),
    organization: (organization || "").trim(),
    email: (email || "").trim(),
    status: "pending",
    createdAt: new Date().toISOString()
  };

  store.requests.unshift(request);
  addAudit(store, "提交证书申请", `${request.commonName} 创建了证书申请`);
  saveStore(store);
  res.status(201).json(request);
});

app.post("/api/requests/:id/approve", (req, res) => {
  const store = loadStore();
  const request = store.requests.find((item) => item.id === req.params.id);
  if (!request) {
    return res.status(404).json({ message: "申请不存在" });
  }
  if (request.status !== "pending") {
    return res.status(400).json({ message: "只有待审核申请可以签发" });
  }

  const issued = issueCertificate(request.commonName, request.organization, request.email);
  const certificate = {
    id: crypto.randomUUID(),
    requestId: request.id,
    owner: request.commonName,
    organization: request.organization,
    email: request.email,
    status: "active",
    issuedAt: new Date().toISOString(),
    revokedAt: null,
    revokeReason: "",
    ...issued
  };

  request.status = "approved";
  request.approvedAt = new Date().toISOString();
  store.certificates.unshift(certificate);
  addAudit(store, "签发证书", `CA 为 ${certificate.owner} 签发证书 ${certificate.serialNumber}`);
  saveStore(store);
  res.status(201).json({ ...certificate, privateKeyPem: undefined });
});

app.post("/api/certificates/:id/revoke", (req, res) => {
  const store = loadStore();
  const cert = store.certificates.find((item) => item.id === req.params.id);
  if (!cert) {
    return res.status(404).json({ message: "证书不存在" });
  }
  if (cert.status === "revoked") {
    return res.status(400).json({ message: "证书已经被吊销" });
  }

  cert.status = "revoked";
  cert.revokedAt = new Date().toISOString();
  cert.revokeReason = req.body.reason || "keyCompromise";
  addAudit(store, "吊销证书", `${cert.owner} 的证书被吊销，原因：${cert.revokeReason}`);
  saveStore(store);
  res.json(cert);
});

app.get("/api/certificates/:id/download/:kind", (req, res) => {
  const store = loadStore();
  const cert = store.certificates.find((item) => item.id === req.params.id);
  if (!cert) {
    return res.status(404).send("证书不存在");
  }

  const downloads = {
    cert: { name: `${cert.owner}-certificate.pem`, data: cert.certificatePem },
    key: { name: `${cert.owner}-private-key.pem`, data: cert.privateKeyPem },
    public: { name: `${cert.owner}-public-key.pem`, data: cert.publicKeyPem }
  };
  const item = downloads[req.params.kind];
  if (!item) {
    return res.status(404).send("下载类型不存在");
  }

  res.setHeader("Content-Type", "application/x-pem-file");
  res.setHeader("Content-Disposition", `attachment; filename="${encodeURIComponent(item.name)}"`);
  res.send(item.data);
});

app.get("/api/crl", (req, res) => {
  const store = loadStore();
  res.json({
    issuer: "Mini PKI Demo Root CA",
    generatedAt: new Date().toISOString(),
    revokedCertificates: store.certificates
      .filter((item) => item.status === "revoked")
      .map((item) => ({
        serialNumber: item.serialNumber,
        owner: item.owner,
        revokedAt: item.revokedAt,
        reason: item.revokeReason
      }))
  });
});

app.post("/api/sign", upload.single("file"), (req, res) => {
  try {
    const store = loadStore();
    const cert = findActiveCertificate(store, req.body.certificateId);
    if (!req.file) {
      return res.status(400).json({ message: "请上传需要签名的文件" });
    }

    const signature = crypto.sign("sha256", req.file.buffer, cert.privateKeyPem).toString("base64");
    addAudit(store, "文件签名", `${cert.owner} 使用证书 ${cert.serialNumber} 签名文件 ${req.file.originalname}`);
    saveStore(store);
    res.json({
      fileName: req.file.originalname,
      algorithm: "RSA-SHA256",
      certificateId: cert.id,
      serialNumber: cert.serialNumber,
      signature,
      fileHash: crypto.createHash("sha256").update(req.file.buffer).digest("hex")
    });
  } catch (error) {
    res.status(error.status || 500).json({ message: error.message });
  }
});

app.post("/api/verify", upload.single("file"), (req, res) => {
  try {
    const store = loadStore();
    const cert = store.certificates.find((item) => item.id === req.body.certificateId);
    if (!cert) {
      return res.status(404).json({ message: "证书不存在" });
    }
    if (!req.file) {
      return res.status(400).json({ message: "请上传原始文件" });
    }
    if (!req.body.signature) {
      return res.status(400).json({ message: "请填写 Base64 签名值" });
    }

    const isSignatureValid = crypto.verify(
      "sha256",
      req.file.buffer,
      cert.publicKeyPem,
      Buffer.from(req.body.signature, "base64")
    );
    const isChainValid = verifyCertificateIssuedByCa(cert.certificatePem);
    const isActive = cert.status === "active";

    res.json({
      valid: isSignatureValid && isChainValid && isActive,
      checks: {
        signature: isSignatureValid,
        caChain: isChainValid,
        certificateStatus: cert.status
      },
      fileHash: crypto.createHash("sha256").update(req.file.buffer).digest("hex")
    });
  } catch (error) {
    res.status(error.status || 500).json({ message: error.message });
  }
});

app.post("/api/sm4/encrypt", upload.single("file"), (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ message: "请上传需要加密的文件" });
    }

    const store = loadStore();
    const key = asHexSm4Key(req.body.keyHex || store.sm4KeyHex);
    const encryptedHex = sm4.encrypt(req.file.buffer.toString("hex"), key);
    addAudit(store, "SM4 加密", `使用 SM4-ECB 加密文件 ${req.file.originalname}`);
    saveStore(store);
    res.json({
      fileName: req.file.originalname,
      keyHex: key,
      mode: "SM4-ECB",
      encryptedHex,
      originalHash: crypto.createHash("sha256").update(req.file.buffer).digest("hex")
    });
  } catch (error) {
    res.status(error.status || 500).json({ message: error.message });
  }
});

app.post("/api/sm4/decrypt", (req, res) => {
  try {
    const store = loadStore();
    const key = asHexSm4Key(req.body.keyHex || store.sm4KeyHex);
    if (!req.body.encryptedHex) {
      return res.status(400).json({ message: "请填写密文十六进制内容" });
    }

    const plainHex = sm4.decrypt(req.body.encryptedHex.trim(), key);
    const plainBuffer = Buffer.from(plainHex, "hex");
    addAudit(store, "SM4 解密", "使用 SM4-ECB 解密密文");
    saveStore(store);
    res.json({
      keyHex: key,
      plainTextPreview: plainBuffer.toString("utf8").slice(0, 500),
      plainHex,
      plainHash: crypto.createHash("sha256").update(plainBuffer).digest("hex")
    });
  } catch (error) {
    res.status(error.status || 500).json({ message: "SM4 解密失败，请检查密钥和密文" });
  }
});

app.use((err, req, res, next) => {
  res.status(500).json({ message: err.message || "服务器内部错误" });
});

const server = app.listen(PORT, "127.0.0.1", () => {
  getCaMaterial();
  loadStore();
  console.log(`Mini PKI RSA/SM4 demo running at http://127.0.0.1:${server.address().port}`);
});
