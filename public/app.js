let state = {
  certificates: [],
  requests: [],
  auditLogs: [],
  sm4KeyHex: ""
};

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => Array.from(document.querySelectorAll(selector));

function toast(message, isError = false) {
  const node = $("#toast");
  node.textContent = message;
  node.style.background = isError ? "#d85d49" : "#17685f";
  node.classList.add("show");
  window.setTimeout(() => node.classList.remove("show"), 2600);
}

async function api(path, options = {}) {
  const response = await fetch(path, options);
  const contentType = response.headers.get("content-type") || "";
  const body = contentType.includes("application/json") ? await response.json() : await response.text();
  if (!response.ok) {
    throw new Error(body.message || body || "请求失败");
  }
  return body;
}

async function refresh() {
  state = await api("/api/overview");
  render();
}

function render() {
  $("#pendingCount").textContent = state.counts.pending;
  $("#issuedCount").textContent = state.counts.issued;
  $("#revokedCount").textContent = state.counts.revoked;
  $("#caCert").value = state.caCertificatePem;
  $("#sm4KeyInput").value = state.sm4KeyHex;
  $("#sm4DecryptKey").value = state.sm4KeyHex;
  renderRequests();
  renderCertificates();
  renderSelects();
  renderAudit();
}

function renderRequests() {
  const pending = state.requests.filter((item) => item.status === "pending");
  $("#requestList").innerHTML = pending.length
    ? pending.map((item) => `
      <article class="row">
        <div>
          <strong>${escapeHtml(item.commonName)}</strong>
          <small>${escapeHtml(item.organization || "未填写组织")} · ${escapeHtml(item.email || "未填写邮箱")} · ${formatDate(item.createdAt)}</small>
        </div>
        <div class="actions">
          <button type="button" data-approve="${item.id}">签发证书</button>
        </div>
      </article>
    `).join("")
    : `<p class="empty">暂无待审核申请。</p>`;
}

function renderCertificates() {
  $("#certList").innerHTML = state.certificates.length
    ? state.certificates.map((item) => `
      <article class="row">
        <div>
          <strong>${escapeHtml(item.owner)} <span class="status ${item.status === "revoked" ? "revoked" : ""}">${item.status === "active" ? "有效" : "已吊销"}</span></strong>
          <small>序列号：${item.serialNumber}</small>
          <small>有效期：${formatDate(item.validFrom)} 至 ${formatDate(item.validTo)}</small>
          <small>指纹：${item.fingerprint}</small>
        </div>
        <div class="actions">
          <a href="/api/certificates/${item.id}/download/cert">证书</a>
          <a href="/api/certificates/${item.id}/download/public">公钥</a>
          <a href="/api/certificates/${item.id}/download/key">私钥</a>
          ${item.status === "active" ? `<button class="danger" type="button" data-revoke="${item.id}">吊销</button>` : ""}
        </div>
      </article>
    `).join("")
    : `<p class="empty">还没有签发证书。</p>`;
}

function renderSelects() {
  const activeCerts = state.certificates.filter((item) => item.status === "active");
  const options = activeCerts.length
    ? activeCerts.map((item) => `<option value="${item.id}">${escapeHtml(item.owner)} · ${item.serialNumber.slice(0, 8)}</option>`).join("")
    : `<option value="">暂无有效证书</option>`;
  $$(".certSelect").forEach((select) => {
    select.innerHTML = options;
  });
}

function renderAudit() {
  $("#auditList").innerHTML = state.auditLogs.length
    ? state.auditLogs.map((item) => `
      <article class="row">
        <div>
          <strong>${escapeHtml(item.action)}</strong>
          <small>${escapeHtml(item.detail)} · ${formatDate(item.at)}</small>
        </div>
      </article>
    `).join("")
    : `<p class="empty">暂无审计日志。</p>`;
}

function formatDate(value) {
  return new Date(value).toLocaleString("zh-CN", { hour12: false });
}

function escapeHtml(value) {
  return String(value || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function wireTabs() {
  $$(".tab").forEach((tab) => {
    tab.addEventListener("click", () => {
      $$(".tab").forEach((item) => item.classList.remove("active"));
      $$(".panel").forEach((item) => item.classList.remove("active"));
      tab.classList.add("active");
      $(`#${tab.dataset.tab}`).classList.add("active");
    });
  });
}

function wireForms() {
  $("#requestForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    try {
      await api("/api/requests", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(Object.fromEntries(form.entries()))
      });
      event.currentTarget.reset();
      await refresh();
      toast("证书申请已提交");
    } catch (error) {
      toast(error.message, true);
    }
  });

  $("#requestList").addEventListener("click", async (event) => {
    const id = event.target.dataset.approve;
    if (!id) return;
    try {
      await api(`/api/requests/${id}/approve`, { method: "POST" });
      await refresh();
      toast("证书已签发");
    } catch (error) {
      toast(error.message, true);
    }
  });

  $("#certList").addEventListener("click", async (event) => {
    const id = event.target.dataset.revoke;
    if (!id) return;
    try {
      await api(`/api/certificates/${id}/revoke`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ reason: "cessationOfOperation" })
      });
      await refresh();
      toast("证书已吊销");
    } catch (error) {
      toast(error.message, true);
    }
  });

  $("#signForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      const result = await api("/api/sign", { method: "POST", body: new FormData(event.currentTarget) });
      $("#signatureOutput").value = result.signature;
      $("#verifyForm textarea[name='signature']").value = result.signature;
      toast("签名已生成");
    } catch (error) {
      toast(error.message, true);
    }
  });

  $("#verifyForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      const result = await api("/api/verify", { method: "POST", body: new FormData(event.currentTarget) });
      $("#verifyResult").textContent = result.valid
        ? `验签通过。文件 SHA-256：${result.fileHash}`
        : `验签失败。签名：${result.checks.signature}，证书链：${result.checks.caChain}，状态：${result.checks.certificateStatus}`;
      toast(result.valid ? "验签通过" : "验签失败", !result.valid);
    } catch (error) {
      toast(error.message, true);
    }
  });

  $("#sm4EncryptForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      const result = await api("/api/sm4/encrypt", { method: "POST", body: new FormData(event.currentTarget) });
      $("#cipherOutput").value = result.encryptedHex;
      $("#sm4DecryptForm textarea[name='encryptedHex']").value = result.encryptedHex;
      $("#sm4DecryptKey").value = result.keyHex;
      toast("SM4 加密完成");
    } catch (error) {
      toast(error.message, true);
    }
  });

  $("#sm4DecryptForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      const result = await api("/api/sm4/decrypt", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(Object.fromEntries(new FormData(event.currentTarget).entries()))
      });
      $("#plainOutput").value = result.plainTextPreview || result.plainHex;
      toast("SM4 解密完成");
    } catch (error) {
      toast(error.message, true);
    }
  });

  $("#loadCrl").addEventListener("click", async () => {
    try {
      const result = await api("/api/crl");
      $("#crlOutput").textContent = JSON.stringify(result, null, 2);
    } catch (error) {
      toast(error.message, true);
    }
  });

  $("#refreshRequests").addEventListener("click", refresh);
}

wireTabs();
wireForms();
refresh().catch((error) => toast(error.message, true));
