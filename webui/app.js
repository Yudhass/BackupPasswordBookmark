"use strict";

let state = []; // [{id, label, kind, profiles: [{name, checked}]}]
let lastRows = 0;

const $ = (id) => document.getElementById(id);
const statusEl = $("status");

function setStatus(text, cls) {
  statusEl.textContent = text;
  statusEl.className = cls || "";
}

function updateSelCount() {
  const n = state.reduce((a, b) => a + b.profiles.filter((p) => p.checked).length, 0);
  $("selCount").textContent = n;
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
  const lamp = document.querySelector(".lamp");
  const badge = $("adminBadge");
  badge.textContent = data.admin
    ? "Administrator aktif — password v20 bisa dibuka."
    : "Tanpa administrator — password v20 terkunci, bookmark tetap jalan.";
  lamp.classList.toggle("ok", !!data.admin);
  $("adminDot").setAttribute("aria-label", data.admin ? "aktif" : "nonaktif");

  state = (data.browsers || []).map((b) => ({
    id: b.id, label: b.label, kind: b.kind,
    profiles: (b.profiles || []).map((p) => ({ name: p, checked: true })),
  }));
  renderSources();
  updateSelCount();
  setStatus(state.length ? "Siap. Pilih sumber di kiri, lalu tekan Backup sekarang." : "Tidak ada browser terdeteksi.", state.length ? "" : "error");
  loadFolderSuggestions();
}

async function loadFolderSuggestions() {
  let data;
  try {
    const res = await fetch("/api/folders");
    data = await res.json();
  } catch (e) {
    return;
  }
  const dl = $("outSuggest");
  const quick = $("outQuick");
  dl.innerHTML = "";
  quick.innerHTML = "";
  (data.suggestions || []).forEach((s) => {
    const opt = document.createElement("option");
    opt.value = s.path;
    opt.label = s.label;
    dl.append(opt);
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "tool mini";
    btn.textContent = s.label;
    btn.title = s.path;
    btn.addEventListener("click", () => {
      $("outDir").value = s.path;
      $("outDir").focus();
    });
    quick.append(btn);
  });
  if (data.default && !$("outDir").value) $("outDir").value = data.default;
}

function renderSources() {
  const box = $("browserList");
  const filter = ($("srcSearch").value || "").toLowerCase().trim();
  box.innerHTML = "";
  if (!state.length) {
    box.innerHTML = "<p class='hint'>Tidak ada browser terdeteksi. Install Chrome, Edge, atau Firefox lalu tekan Muat ulang.</p>";
    return;
  }
  state.forEach((b, bi) => {
    const matchB = b.label.toLowerCase().includes(filter) || b.id.includes(filter);
    const visProfiles = b.profiles.filter((p) => !filter || matchB || p.name.toLowerCase().includes(filter));
    if (filter && !matchB && !visProfiles.length) return;

    const g = document.createElement("div");
    g.className = "bgroup";
    const head = document.createElement("label");
    head.className = "check bhead";
    const all = document.createElement("input");
    all.type = "checkbox";
    all.checked = b.profiles.length > 0 && b.profiles.every((p) => p.checked);
    all.setAttribute("aria-label", "Semua profil " + b.label);
    all.addEventListener("change", () => {
      b.profiles.forEach((p) => (p.checked = all.checked));
      renderSources();
      updateSelCount();
    });
    const name = document.createElement("span");
    const picked = b.profiles.filter((p) => p.checked).length;
    name.innerHTML = "<span class='bname'></span><span class='bkind'></span>";
    name.querySelector(".bname").textContent = b.label;
    name.querySelector(".bkind").textContent = b.kind === "firefox" ? "Firefox" : "Chromium";
    const cnt = document.createElement("span");
    cnt.className = "bcount";
    cnt.textContent = picked + "/" + b.profiles.length;
    head.append(all, name);
    g.append(head);
    g.querySelector(".bhead").append(cnt);

    const ul = document.createElement("ul");
    ul.className = "plist";
    b.profiles.forEach((p) => {
      if (filter && !matchB && !p.name.toLowerCase().includes(filter)) return;
      const pi = b.profiles.indexOf(p);
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
        updateSelCount();
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
  if (!box.children.length) {
    box.innerHTML = "<p class='hint'>Tidak cocok dengan pencarian. Kosongkan kolom cari.</p>";
  }
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
  const old = btn.innerHTML;
  btn.innerHTML = "Membackup…";
  setStatus("Membackup " + sels.length + " profil…");

  let data;
  const outName = (($("outDir").value || "").trim() || "hasil-backup");
  try {
    const res = await fetch("/api/backup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ selections: sels, show: $("showPw").checked, output: outName }),
    });
    data = await res.json();
    if (!res.ok) throw new Error(data.error || "Backup gagal.");
  } catch (e) {
    setStatus(e.message, "error");
    btn.disabled = false;
    btn.innerHTML = old;
    return;
  }
  renderResults(data);
  btn.disabled = false;
  btn.innerHTML = old;
}

function esc(s) {
  return String(s == null ? "" : s);
}

function renderResults(data) {
  const meta = $("resultMeta");
  const tbody = $("resultBody");
  const table = $("resultTable");
  meta.innerHTML = "";
  tbody.innerHTML = "";
  $("emptyNote").hidden = true;

  let totalP = 0, totalB = 0, locked = 0, okProf = 0;
  (data.results || []).forEach((r) => {
    const sum = document.createElement("p");
    sum.className = "sum";
    if (r.error) {
      sum.classList.add("bad");
      sum.textContent = (r.label || r.browser) + " / " + r.profile + ": " + r.error;
      meta.append(sum);
    } else {
      okProf++;
      totalP += r.passwords;
      totalB += r.bookmarks;
      if (/terkunci|butuh Administrator|Administrator/i.test(r.note || "")) locked++;
      const who = document.createElement("span");
      who.className = "who";
      who.textContent = r.label + " / " + r.profile + ": ";
      sum.append(who, document.createTextNode(r.passwords + " password, " + r.bookmarks + " bookmark. " + (r.note || "")));
      meta.append(sum);
      const files = document.createElement("p");
      files.className = "files";
      files.textContent = "Tersimpan: " + (r.files || []).join("  |  ");
      meta.append(files);
      (r.logins || []).forEach((l) => {
        const tr = document.createElement("tr");
        tr.className = "fresh";
        tr.dataset.search = (l.url + " " + l.username).toLowerCase();
        const cells = [r.label, r.profile, l.url, l.username, l.password];
        cells.forEach((v, i) => {
          const td = document.createElement("td");
          td.textContent = esc(v);
          if (i === 2) td.className = "url";
          if (i === 4) td.className = "pw";
          tr.append(td);
        });
        tbody.append(tr);
      });
    }
  });

  // Strip highlight setelah terlihat (satu momen gerak, bukan animasi tiap section).
  setTimeout(() => tbody.querySelectorAll("tr.fresh").forEach((tr) => tr.classList.remove("fresh")), 1600);

  const strip = $("statsStrip");
  strip.hidden = false;
  $("statProf").textContent = okProf;
  $("statP").textContent = totalP;
  $("statB").textContent = totalB;

  const hasRows = tbody.rows.length > 0;
  table.hidden = !hasRows;
  $("deskTools").hidden = !hasRows;
  applyFilter();

  if (data.output) {
    $("outPathNote").textContent = data.output;
    $("outPathNote").title = data.output;
  }

  let msg = totalP + " password dan " + totalB + " bookmark tersimpan di " + data.output + ".";
  const adminOk = document.querySelector(".lamp").classList.contains("ok");
  if (locked && !adminOk) msg += " Sebagian password v20 terkunci — tutup dan jalankan sebagai administrator untuk membukanya.";
  if (locked && adminOk) msg += " Sudah admin tapi sebagian masih terkunci — jalankan 'python app.py --diagnosa' di terminal admin.";
  setStatus(msg, "good");
}

function applyFilter() {
  const q = ($("q").value || "").toLowerCase().trim();
  let shown = 0;
  $("resultBody").querySelectorAll("tr").forEach((tr) => {
    const hit = !q || (tr.dataset.search || "").includes(q);
    tr.style.display = hit ? "" : "none";
    if (hit) shown++;
  });
  lastRows = shown;
  $("rowCount").textContent = $("resultBody").rows.length
    ? "Menampilkan " + shown + " dari " + $("resultBody").rows.length + " baris"
    : "";
}

async function copyVisible() {
  const lines = [];
  $("resultBody").querySelectorAll("tr").forEach((tr) => {
    if (tr.style.display === "none") return;
    const tds = tr.querySelectorAll("td");
    lines.push([tds[0].textContent, tds[1].textContent, tds[2].textContent, tds[3].textContent, tds[4].textContent].join("\t"));
  });
  if (!lines.length) {
    setStatus("Tidak ada baris tampil untuk disalin.", "error");
    return;
  }
  try {
    await navigator.clipboard.writeText(lines.join("\n"));
    setStatus(lines.length + " baris tersalin ke clipboard. Tempel di spreadsheet, lalu hapus setelah dipakai.", "good");
  } catch (e) {
    setStatus("Clipboard ditolak browser. Blokir tabel secara manual.", "error");
  }
}

$("allBtn").addEventListener("click", () => {
  state.forEach((b) => b.profiles.forEach((p) => (p.checked = true)));
  renderSources();
  updateSelCount();
});
$("noneBtn").addEventListener("click", () => {
  state.forEach((b) => b.profiles.forEach((p) => (p.checked = false)));
  renderSources();
  updateSelCount();
});
$("refreshBtn").addEventListener("click", loadBrowsers);
$("backupBtn").addEventListener("click", doBackup);
$("srcSearch").addEventListener("input", renderSources);
$("q").addEventListener("input", applyFilter);
$("copyBtn").addEventListener("click", copyVisible);
$("resetOut").addEventListener("click", () => {
  $("outDir").value = "hasil-backup";
  $("outDir").focus();
});
$("copyPathBtn").addEventListener("click", async () => {
  const p = $("outPathNote").title || $("outPathNote").textContent;
  try {
    await navigator.clipboard.writeText(p);
    setStatus("Path tersalin: " + p, "good");
  } catch (e) {
    setStatus("Clipboard ditolak browser. Blok path secara manual.", "error");
  }
});

loadBrowsers();
