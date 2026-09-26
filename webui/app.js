"use strict";

let state = []; // [{id, label, kind, profiles: [{name, checked}]}]

const $ = (id) => document.getElementById(id);
const statusEl = $("status");

function setStatus(text, cls) {
  statusEl.textContent = text;
  statusEl.className = cls || "";
}

async function loadBrowsers() {
  setStatus("Memuat daftar browser…");
  let data;
  try {
    const res = await fetch("/api/browsers");
    data = await res.json();
  } catch (e) {
    setStatus("Server tidak menjawab. Tutup halaman ini dan jalankan ulang app.py --web.", "error");
    return;
  }
  const badge = $("adminBadge");
  badge.textContent = data.admin
    ? "Administrator aktif — password v20 bisa dibuka"
    : "Tanpa administrator — password v20 terkunci";
  badge.classList.toggle("ok", !!data.admin);

  state = (data.browsers || []).map((b) => ({
    id: b.id, label: b.label, kind: b.kind,
    profiles: (b.profiles || []).map((p) => ({ name: p, checked: true })),
  }));
  renderSources();
  setStatus(state.length ? "Siap." : "Tidak ada browser terdeteksi.", state.length ? "" : "error");
}

function renderSources() {
  const box = $("browserList");
  box.innerHTML = "";
  if (!state.length) {
    box.innerHTML = "<p class='hint'>Tidak ada browser terdeteksi. Install Chrome, Edge, atau Firefox lalu tekan Muat ulang.</p>";
    return;
  }
  state.forEach((b, bi) => {
    const g = document.createElement("div");
    g.className = "bgroup";
    const head = document.createElement("label");
    head.className = "check bhead";
    const all = document.createElement("input");
    all.type = "checkbox";
    all.checked = b.profiles.every((p) => p.checked);
    all.setAttribute("aria-label", "Semua profil " + b.label);
    all.addEventListener("change", () => {
      b.profiles.forEach((p) => (p.checked = all.checked));
      renderSources();
    });
    const name = document.createElement("span");
    name.innerHTML = "<span class='bname'></span> <span class='bkind'></span>";
    name.querySelector(".bname").textContent = b.label;
    name.querySelector(".bkind").textContent = b.kind === "firefox" ? "Firefox" : "Chromium";
    head.append(all, name);
    g.append(head);

    const ul = document.createElement("ul");
    ul.className = "plist";
    b.profiles.forEach((p, pi) => {
      const li = document.createElement("li");
      const lab = document.createElement("label");
      lab.className = "check";
      const cb = document.createElement("input");
      cb.type = "checkbox";
      cb.checked = p.checked;
      cb.setAttribute("aria-label", b.label + " profil " + p.name);
      cb.addEventListener("change", () => {
        state[bi].profiles[pi].checked = cb.checked;
        renderSources();
      });
      const t = document.createElement("span");
      t.textContent = p.name;
      lab.append(cb, t);
      li.append(lab);
      ul.append(li);
    });
    g.append(ul);
    box.append(g);
  });
}

function selected() {
  const out = [];
  state.forEach((b) =>
    b.profiles.forEach((p) => {
      if (p.checked) out.push({ browser: b.id, profile: p.name });
    })
  );
  return out;
}

async function doBackup() {
  const sels = selected();
  if (!sels.length) {
    setStatus("Pilih minimal satu browser dan profil dahulu.", "error");
    return;
  }
  const btn = $("backupBtn");
  btn.disabled = true;
  const old = btn.textContent;
  btn.textContent = "Membackup…";
  setStatus("Membackup " + sels.length + " profil…");

  let data;
  try {
    const res = await fetch("/api/backup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ selections: sels, show: $("showPw").checked }),
    });
    data = await res.json();
    if (!res.ok) throw new Error(data.error || "Backup gagal.");
  } catch (e) {
    setStatus(e.message, "error");
    btn.disabled = false;
    btn.textContent = old;
    return;
  }
  renderResults(data);
  btn.disabled = false;
  btn.textContent = old;
}

function renderResults(data) {
  const meta = $("resultMeta");
  const tbody = $("resultBody");
  const table = $("resultTable");
  meta.innerHTML = "";
  tbody.innerHTML = "";
  $("emptyNote").hidden = true;

  let totalP = 0, totalB = 0, locked = 0;
  (data.results || []).forEach((r) => {
    const sum = document.createElement("p");
    sum.className = "sum";
    if (r.error) {
      sum.classList.add("bad");
      sum.textContent = (r.label || r.browser) + " / " + r.profile + ": " + r.error;
    } else {
      totalP += r.passwords;
      totalB += r.bookmarks;
      if (/terkunci|butuh Administrator|terkunci/.test(r.note)) locked++;
      sum.textContent =
        r.label + " / " + r.profile + ": " + r.passwords + " password, " +
        r.bookmarks + " bookmark. " + r.note;
      const files = document.createElement("p");
      files.className = "files";
      files.textContent = "Tersimpan: " + (r.files || []).join("  |  ");
      meta.append(sum, files);
      (r.logins || []).forEach((l) => {
        const tr = document.createElement("tr");
        [r.label, r.profile, l.url, l.username, l.password].forEach((v, i) => {
          const td = document.createElement("td");
          td.textContent = v;
          if (i === 2) td.className = "url";
          if (i === 4) td.className = "pw";
          tr.append(td);
        });
        tbody.append(tr);
      });
    }
    if (r.error) meta.append(sum);
  });

  table.hidden = tbody.rows.length === 0;
  let msg = totalP + " password dan " + totalB + " bookmark tersimpan di " + data.output + ".";
  const adminOk = document.getElementById("adminBadge").classList.contains("ok");
  if (locked && !adminOk) msg += " Sebagian password v20 terkunci — tutup dan jalankan sebagai administrator untuk membukanya.";
  if (locked && adminOk) msg += " Sudah admin tapi sebagian password v20 masih terkunci — jalankan 'python app.py --diagnosa' di terminal admin dan ikuti petunjuknya.";
  setStatus(msg, "good");
}

$("allBtn").addEventListener("click", () => {
  state.forEach((b) => b.profiles.forEach((p) => (p.checked = true)));
  renderSources();
});
$("noneBtn").addEventListener("click", () => {
  state.forEach((b) => b.profiles.forEach((p) => (p.checked = false)));
  renderSources();
});
$("refreshBtn").addEventListener("click", loadBrowsers);
$("backupBtn").addEventListener("click", doBackup);

loadBrowsers();
