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

async function copyToken(id, btn) {
    const el = document.getElementById(id);
    const value = (el && el.value ? el.value : "").trim();
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

    if (!copied) {
        const prevType = el.type;
        try {
            if (prevType === "password") el.type = "text";
            el.select();
            copied = document.execCommand("copy");
        } catch (_) {
            copied = false;
        } finally {
            el.type = prevType;
            window.getSelection()?.removeAllRanges();
        }
    }

    btn.textContent = copied ? "Tersalin" : "Gagal";
    setTimeout(function() { btn.textContent = original; }, 1500);
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
