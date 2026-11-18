function escapeHtml(s) {
    if (typeof s === "number") return String(s);
    return String(s || "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
}

function setConnectionState(state, message) {
    const badge = document.getElementById("connStatus");
    badge.classList.toggle("is-authed", state === "ready");
    badge.classList.toggle("is-error", state === "error");
    document.getElementById("connText").textContent = message;
}

function toggleVis(id, btn) {
    const el = document.getElementById(id);
    const show = el.type === "password";
    el.type = show ? "text" : "password";
    btn.textContent = show ? "Sembunyikan" : "Lihat";
    btn.setAttribute("aria-pressed", String(show));
}

async function copyTextValue(value, btn, fallbackInputEl) {
    const original = btn.dataset.label || btn.textContent;
    btn.dataset.label = original;

    if (!value) {
        btn.textContent = "Kosong";
        setTimeout(function() { btn.textContent = original; }, 1200);
        return;
    }

    let copied = false;
    if (navigator.clipboard && navigator.clipboard.writeText) {
        try {
            await navigator.clipboard.writeText(value);
            copied = true;
        } catch (_) {
            copied = false;
        }
    }

    if (!copied && fallbackInputEl) {
        const prevType = fallbackInputEl.type;
        try {
            if (prevType === "password") fallbackInputEl.type = "text";
            fallbackInputEl.select();
            copied = document.execCommand("copy");
        } catch (_) {
            copied = false;
        } finally {
            fallbackInputEl.type = prevType;
            window.getSelection()?.removeAllRanges();
        }
    }

    if (!copied && !fallbackInputEl) {
        const tempArea = document.createElement("textarea");
        tempArea.value = value;
        tempArea.setAttribute("readonly", "");
        tempArea.style.position = "fixed";
        tempArea.style.opacity = "0";
        document.body.appendChild(tempArea);
        try {
            tempArea.select();
            copied = document.execCommand("copy");
        } catch (_) {
            copied = false;
        } finally {
            document.body.removeChild(tempArea);
            window.getSelection()?.removeAllRanges();
        }
    }

    btn.textContent = copied ? "Tersalin" : "Gagal";
    setTimeout(function() { btn.textContent = original; }, 1500);
}

async function copyToken(id, btn) {
    const el = document.getElementById(id);
    const value = (el && el.value ? el.value : "").trim();
    await copyTextValue(value, btn, el);
}

async function copyDataUtamaJson(btn) {
    const pre = document.getElementById("dataUtamaJson");
    const value = (pre && pre.textContent ? pre.textContent : "").trim();
    await copyTextValue(value, btn, null);
}

function clearDataUtamaResult() {
    const resultEl = document.getElementById("dataUtamaResult");
    const panelEl = document.getElementById("dataUtamaResponsePanel");
    const summaryEl = document.getElementById("dataUtamaSummary");
    const jsonEl = document.getElementById("dataUtamaJson");
    if (resultEl) resultEl.textContent = "";
    if (summaryEl) {
        summaryEl.innerHTML = "";
        summaryEl.hidden = true;
    }
    if (jsonEl) jsonEl.textContent = "";
    if (panelEl) panelEl.hidden = true;
}

function renderDataUtamaSummary(payload) {
    const summaryEl = document.getElementById("dataUtamaSummary");
    if (!summaryEl) return;
    summaryEl.innerHTML = "";

    const record = payload && typeof payload === "object" && payload.data && typeof payload.data === "object"
        ? payload.data
        : payload;
    if (!record || typeof record !== "object") {
        summaryEl.hidden = true;
        return;
    }

    const fullName = [record.gelarDepan, record.nama, record.gelarBelakang]
        .map(function(part) { return typeof part === "string" ? part.trim() : ""; })
        .filter(Boolean)
        .join(" ");

    const items = [
        ["Nama", fullName || record.nama],
        ["NIP Baru", record.nipBaru],
        ["Golongan", record.golonganAkhirNama || record.golonganAkhirKode],
        ["Status", record.kedudukanHukumNama || record.statusPegawai],
    ].filter(function(entry) {
        return typeof entry[1] === "string" && entry[1].trim() !== "";
    });

    if (items.length === 0) {
        summaryEl.hidden = true;
        return;
    }

    items.forEach(function(entry) {
        const box = document.createElement("div");
        box.className = "summary-item";

        const label = document.createElement("span");
        label.className = "summary-label";
        label.textContent = entry[0];

        const value = document.createElement("span");
        value.className = "summary-value";
        value.textContent = entry[1].trim();

        box.appendChild(label);
        box.appendChild(value);
        summaryEl.appendChild(box);
    });
    summaryEl.hidden = false;
}

async function fetchDataUtama() {
    const nipEl = document.getElementById("nipInput");
    const accessTokenEl = document.getElementById("accessToken");
    const authHeaderEl = document.getElementById("authHeaderToken");
    const dataUtamaUrlEl = document.getElementById("dataUtamaUrl");
    const btn = document.getElementById("btnFetchDataUtama");
    const resultEl = document.getElementById("dataUtamaResult");
    const panelEl = document.getElementById("dataUtamaResponsePanel");
    const jsonEl = document.getElementById("dataUtamaJson");

    const nip = (nipEl ? nipEl.value : "").trim();
    const accessToken = (accessTokenEl ? accessTokenEl.value : "").trim();
    const authHeaderToken = (authHeaderEl ? authHeaderEl.value : "").trim();
    const dataUtamaUrl = (dataUtamaUrlEl ? dataUtamaUrlEl.value : "").trim();

    if (!nip) {
        resultEl.innerHTML = '<span class="form-error">NIP wajib diisi.</span>';
        if (nipEl) nipEl.focus();
        return;
    }
    if (!accessToken) {
        resultEl.innerHTML = '<span class="form-error">Authorization Token wajib diisi (uji login atau tempel token terlebih dahulu).</span>';
        if (accessTokenEl) accessTokenEl.focus();
        return;
    }

    btn.disabled = true;
    resultEl.innerHTML = '<span class="form-ok">Mengambil data utama...</span>';

    const fd = new FormData();
    fd.append("nip", nip);
    fd.append("access_token", accessToken);
    fd.append("auth_header_token", authHeaderToken);
    fd.append("data_utama_url", dataUtamaUrl);

    const endpoint = (document.querySelector('meta[name="data-utama-url"]') || {}).content || "datautama.php";

    try {
        const res = await apiPost(endpoint, fd);
        let data = null;
        try {
            data = await res.json();
        } catch (_) {
            data = null;
        }

        if (data && data.ok) {
            resultEl.innerHTML = '<span class="form-ok">' + escapeHtml(data.message) + '</span>';
            renderDataUtamaSummary(data.data);
            jsonEl.textContent = JSON.stringify(data.data ?? {}, null, 2);
            panelEl.hidden = false;
        } else {
            const errMsg = data && data.message ? data.message : ("HTTP " + res.status);
            resultEl.innerHTML = '<span class="form-error">' + escapeHtml(errMsg) + '</span>';
            panelEl.hidden = true;
        }
    } catch (err) {
        resultEl.innerHTML = '<span class="form-error">Kesalahan jaringan: ' + escapeHtml(err.toString()) + '</span>';
        panelEl.hidden = true;
    } finally {
        btn.disabled = false;
    }
}

async function testToken() {
    const btn = document.getElementById("btnTestToken");
    const el = document.getElementById("tokenResult");
    btn.disabled = true;
    el.innerHTML = '<span class="form-ok">Menguji...</span>';
    setConnectionState("idle", "Menguji token...");

    const fd = new FormData();
    fd.append("username", document.getElementById("username").value.trim());
    fd.append("password", document.getElementById("password").value.trim());
    fd.append("token_url", document.getElementById("tokenUrl").value.trim());
    const endpoint = (document.querySelector('meta[name="test-token-url"]') || {}).content || "test-token.php";

    try {
        const res = await apiPost(endpoint, fd);
        const data = await res.json();
        if (data.ok) {
            el.innerHTML = '<span class="form-ok">' + escapeHtml(data.message) + '</span>';
            document.getElementById("accessToken").value = data.access_token || "";
            setConnectionState("ready", "Token berhasil diuji");
        } else {
            el.innerHTML = '<span class="form-error">' + escapeHtml(data.message) + '</span>';
            setConnectionState("error", "Uji token gagal");
        }
    } catch (err) {
        el.innerHTML = '<span class="form-error">Kesalahan jaringan: ' + escapeHtml(err.toString()) + '</span>';
        setConnectionState("error", "Tidak dapat menguji token");
    } finally {
        btn.disabled = false;
    }
}

["username", "password", "tokenUrl"].forEach(function(id) {
    document.getElementById(id).addEventListener("input", function() {
        const token = document.getElementById("accessToken");
        token.value = "";
        token.placeholder = "Kredensial berubah - uji login kembali";
        setConnectionState("idle", "Kredensial berubah · uji token lagi");
    });
});

document.getElementById("accessToken").addEventListener("input", function() {
    if (this.value.trim()) {
        setConnectionState("idle", "Token manual belum diuji");
    } else if (document.getElementById("connText").textContent === "Token manual belum diuji") {
        setConnectionState("idle", "Token belum diuji");
    }
});
