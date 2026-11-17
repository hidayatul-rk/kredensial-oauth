// Token CSRF dibaca dari meta tag dan dikirimkan pada setiap POST.
const CSRF_TOKEN = (document.querySelector('meta[name="csrf-token"]') || {}).content || "";

function apiPost(url, fd) {
    if (fd instanceof FormData) {
        fd.append("csrf_token", CSRF_TOKEN);
    }
    return fetch(url, {
        method: "POST",
        body: fd,
        headers: { "X-CSRF-Token": CSRF_TOKEN },
    });
}
