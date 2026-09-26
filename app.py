#!/usr/bin/env python3
"""
Backup Password & Bookmark Semua Browser (Windows)
==================================================
Backup password + bookmark milik sendiri dari:
  Chromium: Google Chrome, Microsoft Edge, Brave, Opera, Vivaldi, Chromium
  Gecko   : Mozilla Firefox (+ Dev Edition)

Chromium:
- Kunci v10/v11 dari Local State -> DPAPI (ctypes, tanpa pywin32)
- Kunci v20/v21 App-Bound (Chrome 127+) -> butuh "Run as Administrator"
  (SYSTEM impersonation + CNG, murni ctypes)
- Login Data disalin ke temp dulu (aman walau browser terbuka)

Firefox:
- Password di logins.json (terenkripsi NSS) + kunci di key4.db.
  Aplikasi mencoba dekripsi via nss3.dll bawaan Firefox (tanpa master password).
  Jika gagal (ada master password / NSS terkunci), username+URL tetap dibackup
  dan file mentah (logins.json + key4.db + cert9.db) disalin agar bisa di-restore.
- Bookmark dari places.sqlite.

HANYA untuk data milik sendiri. Jaga file hasil (berisi password asli!).

 Hasil backup terpisah folder:
   <output>/passwords/*.csv   (password, format import Chrome)
   <output>/bookmarks/*.html  (Netscape-HTML, import via bookmark manager:
     *-bookmarks-bar_*.html = Bilah bookmark (Bookmarks + Bookmarks.bak),
     *-bookmarks-other_*.html = Bookmark lainnya + Sync/Tab,
     *-riwayat_*.html = Riwayat browser, terpisah agar tak membanjiri bookmark)
 Lihat contoh bentuk file di folder contoh/.

CLI:
    python app.py --list-browsers
    python app.py                                             # semua browser+profil
    python app.py --browser chrome firefox                    # browser tertentu
    python app.py --browser edge --profile Default
    python app.py --gui                                       # mode GUI
"""
import argparse
import base64
import csv
import ctypes
import html
import io
import json
import os
import shutil
import sqlite3
import struct
import sys
import tempfile
from contextlib import contextmanager
from ctypes import wintypes
from datetime import datetime
from pathlib import Path


# ================================================================= DPAPI

class DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD),
                ("pbData", ctypes.POINTER(ctypes.c_char))]


def dpapi_decrypt(data: bytes) -> bytes:
    if os.name != "nt":
        raise OSError("DPAPI hanya tersedia di Windows.")
    buf_in = ctypes.create_string_buffer(data, len(data))
    blob_in = DATA_BLOB(len(data), buf_in)
    blob_out = DATA_BLOB()
    if not ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out)
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(blob_out.pbData)


def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


# ================================================== App-Bound v20 (Chromium)

def _enable_se_debug():
    try:
        adv = ctypes.windll.advapi32
        TOKEN_ADJUST, TOKEN_QUERY, SE_ENABLED = 0x0020, 0x0008, 0x00000002

        class LUID(ctypes.Structure):
            _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]

        class LUID_AND_ATTR(ctypes.Structure):
            _fields_ = [("Luid", LUID), ("Attributes", wintypes.DWORD)]

        class TOKEN_PRIV(ctypes.Structure):
            _fields_ = [("PrivilegeCount", wintypes.DWORD),
                        ("Privileges", LUID_AND_ATTR * 1)]

        h_tok = wintypes.HANDLE()
        adv.OpenProcessToken(ctypes.windll.kernel32.GetCurrentProcess(),
                             TOKEN_ADJUST | TOKEN_QUERY, ctypes.byref(h_tok))
        luid = LUID()
        adv.LookupPrivilegeValueW(None, "SeDebugPrivilege", ctypes.byref(luid))
        tp = TOKEN_PRIV(1, (LUID_AND_ATTR(luid, SE_ENABLED),))
        adv.AdjustTokenPrivileges(h_tok, False, ctypes.byref(tp),
                                  ctypes.sizeof(tp), None, None)
        ctypes.windll.kernel32.CloseHandle(h_tok)
    except Exception:
        pass


def _find_process_pid(name: str):
    """PID proses berdasarkan nama (tanpa psutil). Return int|None."""
    try:
        TH32CS_SNAPPROCESS = 0x00000002

        class PROCESSENTRY32(ctypes.Structure):
            _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
                        ("th32ProcessID", wintypes.DWORD),
                        ("th32DefaultHeapID", ctypes.c_void_p),
                        ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
                        ("th32ParentProcessID", wintypes.DWORD),
                        ("pcPriClassBase", wintypes.LONG), ("dwFlags", wintypes.DWORD),
                        ("szExeFile", ctypes.c_wchar * 260)]

        k32 = ctypes.windll.kernel32
        snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if snap == wintypes.HANDLE(-1).value:
            return None
        try:
            pe = PROCESSENTRY32()
            pe.dwSize = ctypes.sizeof(pe)
            ok = k32.Process32FirstW(snap, ctypes.byref(pe))
            while ok:
                if pe.szExeFile.lower() == name.lower():
                    return pe.th32ProcessID
                ok = k32.Process32NextW(snap, ctypes.byref(pe))
        finally:
            k32.CloseHandle(snap)
    except Exception:
        pass
    return None


@contextmanager
def _impersonate_pid(pid: int):
    adv = ctypes.windll.advapi32
    k32 = ctypes.windll.kernel32
    h_proc = k32.OpenProcess(0x0400, False, pid)
    if not h_proc:
        # Proses terproteksi (mis. LSASS/PPL): coba hak baca terbatas
        h_proc = k32.OpenProcess(0x1000, False, pid)
    if not h_proc:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        h_tok = wintypes.HANDLE()
        if not adv.OpenProcessToken(h_proc, 0x0002 | 0x0004 | 0x0008, ctypes.byref(h_tok)):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            h_imp = wintypes.HANDLE()
            if not adv.DuplicateToken(h_tok, 2, ctypes.byref(h_imp)):
                raise ctypes.WinError(ctypes.get_last_error())
            try:
                if not adv.ImpersonateLoggedOnUser(h_imp):
                    raise ctypes.WinError(ctypes.get_last_error())
                try:
                    yield pid
                finally:
                    adv.RevertToSelf()
            finally:
                k32.CloseHandle(h_imp)
        finally:
            k32.CloseHandle(h_tok)
    finally:
        k32.CloseHandle(h_proc)


@contextmanager
def _impersonate_system():
    """Impersonate token SYSTEM. Dicoba berurutan: lsass -> winlogon -> services.
    LSASS di Windows modern terproteksi (PPL) sehingga OpenProcess sebagai admin
    pun bisa ditolak; fallback ke proses SYSTEM lain biasanya berhasil."""
    _enable_se_debug()
    errors = []
    for name in ("lsass.exe", "winlogon.exe", "services.exe"):
        pid = _find_process_pid(name)
        if not pid:
            errors.append(f"{name} tak ditemukan")
            continue
        try:
            with _impersonate_pid(pid) as used:
                yield used
                return
        except Exception as e:
            errors.append(f"{name}: {e}")
    raise OSError("Impersonasi SYSTEM gagal — " + "; ".join(errors))


def _system_dpapi_decrypt(blob: bytes) -> bytes:
    buf_in = ctypes.create_string_buffer(blob, len(blob))
    blob_in = DATA_BLOB(len(blob), buf_in)
    blob_out = DATA_BLOB()
    if not ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out)
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(blob_out.pbData)


def _parse_appbound_blob(blob: bytes) -> dict:
    buf = io.BytesIO(blob)
    hdr = buf.read(4)
    if len(hdr) < 4:
        raise ValueError("Blob App-Bound terlalu pendek.")
    (header_len,) = struct.unpack("<I", hdr)
    buf.read(header_len)
    clen_raw = buf.read(4)
    if len(clen_raw) < 4:
        raise ValueError("Blob App-Bound rusak.")
    (content_len,) = struct.unpack("<I", clen_raw)
    rest = buf.read()
    if content_len == 32 and len(rest) >= 32:
        return {"flag": 0, "raw_key": rest[:32]}
    if not rest:
        raise ValueError("Blob App-Bound rusak (flag).")
    flag = rest[0]
    if flag in (1, 2):
        if len(rest) < 1 + 12 + 16:
            raise ValueError("Blob App-Bound rusak (flag 1/2).")
        return {"flag": flag, "iv": rest[1:13],
                "ciphertext": rest[13:-16], "tag": rest[-16:]}
    if flag == 3:
        if len(rest) < 1 + 32 + 12 + 16:
            raise ValueError("Blob App-Bound rusak (flag 3).")
        return {"flag": 3, "encrypted_aes_key": rest[1:33],
                "iv": rest[33:45], "ciphertext": rest[45:-16], "tag": rest[-16:]}
    raise ValueError(f"Flag App-Bound tak dikenal: {flag}")


def _cng_decrypt(data: bytes, key_name: str) -> bytes:
    ncrypt = ctypes.windll.LoadLibrary("ncrypt.dll")
    h_prov = ctypes.c_void_p()
    if ncrypt.NCryptOpenStorageProvider(ctypes.byref(h_prov),
                                        "Microsoft Software Key Storage Provider", 0) != 0:
        raise OSError("NCryptOpenStorageProvider gagal.")
    try:
        h_key = ctypes.c_void_p()
        ncrypt.NCryptOpenKey.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p),
                                         wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD]
        ncrypt.NCryptOpenKey.restype = wintypes.DWORD
        if ncrypt.NCryptOpenKey(h_prov, ctypes.byref(h_key), key_name, 0, 0) != 0:
            raise OSError(f"NCryptOpenKey gagal: {key_name}")
        try:
            in_buf = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
            out_len = wintypes.DWORD(0)
            ncrypt.NCryptDecrypt.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ubyte),
                                             wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p,
                                             wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
                                             wintypes.DWORD]
            ncrypt.NCryptDecrypt.restype = wintypes.DWORD
            if ncrypt.NCryptDecrypt(h_key, in_buf, len(data), None, None, 0,
                                    ctypes.byref(out_len), 0x40) != 0:
                raise OSError("NCryptDecrypt (ukur) gagal.")
            out_buf = (ctypes.c_ubyte * out_len.value)()
            if ncrypt.NCryptDecrypt(h_key, in_buf, len(data), None, out_buf,
                                    out_len.value, ctypes.byref(out_len), 0x40) != 0:
                raise OSError("NCryptDecrypt gagal.")
            return bytes(out_buf[:out_len.value])
        finally:
            ncrypt.NCryptFreeObject(h_key)
    finally:
        ncrypt.NCryptFreeObject(h_prov)


def _derive_appbound_master(parsed: dict, cng_keys) -> bytes:
    from Crypto.Cipher import AES
    if parsed["flag"] == 0:
        return parsed["raw_key"]
    if parsed["flag"] == 1:
        k = bytes.fromhex("B31C6E241AC846728DA9C1FAC4936651CFFB944D143AB816276BCC6DA0284787")
        c = AES.new(k, AES.MODE_GCM, nonce=parsed["iv"])
        return c.decrypt_and_verify(parsed["ciphertext"], parsed["tag"])
    if parsed["flag"] == 2:
        from Crypto.Cipher import ChaCha20_Poly1305
        k = bytes.fromhex("E98F37D7F4E1FA433D19304DC2258042090E2D1D7EEA7670D41F738D08729660")
        c = ChaCha20_Poly1305.new(key=k, nonce=parsed["iv"])
        return c.decrypt_and_verify(parsed["ciphertext"], parsed["tag"])
    if parsed["flag"] == 3:
        xor_key = bytes.fromhex("CCF8A1CEC56605B8517552BA1A2D061C03A29E90274FB2FCF59BA4B75C392390")
        last_err = None
        for kn in cng_keys:
            try:
                with _impersonate_system():
                    dec_aes = _cng_decrypt(parsed["encrypted_aes_key"], kn)
                xored = bytes(a ^ b for a, b in zip(dec_aes, xor_key))
                c = AES.new(xored, AES.MODE_GCM, nonce=parsed["iv"])
                return c.decrypt_and_verify(parsed["ciphertext"], parsed["tag"])
            except Exception as e:
                last_err = e
        raise OSError(f"CNG gagal semua kunci ({cng_keys}): {last_err}")
    raise ValueError("Flag App-Bound tak dikenal.")


def _appbound_steps(user_data_dir: Path, cng_keys):
    """Jalankan tiap tahap dekripsi App-Bound dan catat hasilnya (tak pernah raise).
    Return dict: localstate, appbound, sys, user, flag, key, error."""
    st = {"localstate": "?", "appbound": "?", "sys": "?", "user": "?",
          "flag": "?", "key": None, "error": None}
    try:
        with open(user_data_dir / "Local State", "r", encoding="utf-8") as f:
            ls = json.load(f)
        st["localstate"] = "ok"
    except Exception as e:
        st["localstate"] = f"GAGAL: {e}"
        st["error"] = "Local State tak terbaca"
        return st
    b64 = ls.get("os_crypt", {}).get("app_bound_encrypted_key")
    if not b64:
        st["appbound"] = "tak ada (browser lama?)"
        st["error"] = "tidak ada app_bound_encrypted_key"
        return st
    try:
        raw = base64.b64decode(b64)
    except Exception as e:
        st["appbound"] = f"bukan base64: {e}"
        st["error"] = "app_bound key rusak"
        return st
    if raw[:4] != b"APPB":
        st["appbound"] = "awalan bukan APPB"
        st["error"] = "format app_bound bukan APPB"
        return st
    st["appbound"] = f"ok APPB ({len(raw)} byte)"
    if not is_admin():
        st["error"] = "butuh Administrator"
        return st
    try:
        with _impersonate_system() as pid:
            st["sys"] = f"ok (pid {pid})"
            blob_sys = _system_dpapi_decrypt(raw[4:])
    except Exception as e:
        st["sys"] = f"GAGAL: {e}"
        st["error"] = f"SYSTEM DPAPI/impersonasi gagal: {e}"
        return st
    try:
        blob_user = dpapi_decrypt(blob_sys)
        st["user"] = f"ok ({len(blob_user)} byte)"
    except Exception as e:
        st["user"] = f"GAGAL: {e}"
        st["error"] = ("DPAPI user gagal — kemungkinan Anda elevate sebagai AKUN BERBEDA "
                       "(mis. akun Administrator lain), bukan akun pemilik Chrome")
        return st
    try:
        parsed = _parse_appbound_blob(blob_user)
        st["flag"] = str(parsed["flag"])
    except Exception as e:
        st["flag"] = f"GAGAL: {e}"
        st["error"] = f"parse blob gagal: {e}"
        return st
    try:
        st["key"] = _derive_appbound_master(parsed, cng_keys)
    except Exception as e:
        st["error"] = f"turunan kunci gagal (flag {parsed['flag']}): {e}"
        return st
    return st


def get_chromium_keys(user_data_dir: Path, cng_keys):
    """Return (v10key|None, v10err|None, v20key|None, v20info)."""
    v10key, v10err = None, None
    try:
        with open(user_data_dir / "Local State", "r", encoding="utf-8") as f:
            ls = json.load(f)
        enc = base64.b64decode(ls["os_crypt"]["encrypted_key"])
        v10key = dpapi_decrypt(enc[5:] if enc.startswith(b"DPAPI") else enc)
    except Exception as e:
        v10err = str(e)
    st = _appbound_steps(user_data_dir, cng_keys)
    v20info = f"ok (flag {st['flag']})" if st["key"] is not None else (st["error"] or "tanpa kunci v20")
    return v10key, v10err, st["key"], v20info


V20_LOCKED_MSG = "<v20 terkunci: jalankan sebagai Administrator>"


def _aes_gcm_decrypt(iv: bytes, ct_tag: bytes, key: bytes) -> bytes:
    from Crypto.Cipher import AES
    c = AES.new(key, AES.MODE_GCM, nonce=iv)
    return c.decrypt_and_verify(ct_tag[:-16], ct_tag[-16:])


def decrypt_chromium_blob(blob: bytes, v10key, v20key, v20fail=None) -> str:
    if not blob:
        return ""
    if isinstance(blob, memoryview):
        blob = bytes(blob)
    prefix = blob[:3]
    if prefix in (b"v10", b"v11", b"v80"):
        if not v10key:
            return "<tanpa kunci v10>"
        try:
            return _aes_gcm_decrypt(blob[3:15], blob[15:], v10key).decode("utf-8", errors="replace")
        except ImportError:
            return "<butuh pycryptodome>"
        except Exception as e:
            return f"<gagal AES: {e}>"
    if prefix in (b"v20", b"v21"):
        if not v20key:
            return v20fail or V20_LOCKED_MSG
        try:
            return _aes_gcm_decrypt(blob[3:15], blob[15:], v20key).decode("utf-8", errors="replace")
        except ImportError:
            return "<butuh pycryptodome>"
        except Exception as e:
            return f"<gagal AES v20: {e}>"
    try:
        return dpapi_decrypt(blob).decode("utf-8", errors="replace")
    except Exception as e:
        return f"<gagal DPAPI: {e}>"


# ================================================================= Registry browser

def _local(p: str) -> Path:
    return Path(os.environ.get("LOCALAPPDATA", "")) / p


def _roam(p: str) -> Path:
    return Path(os.environ.get("APPDATA", "")) / p


BROWSERS = {
    "chrome":   {"label": "Google Chrome",   "kind": "chromium",
                 "user_data": _local(r"Google\Chrome\User Data"),
                 "cng": ["Google Chromekey1"]},
    "edge":     {"label": "Microsoft Edge",  "kind": "chromium",
                 "user_data": _local(r"Microsoft\Edge\User Data"),
                 "cng": ["Microsoft Edgekey1", "Google Chromekey1"]},
    "brave":    {"label": "Brave",           "kind": "chromium",
                 "user_data": _local(r"BraveSoftware\Brave-Browser\User Data"),
                 "cng": ["Brave Softwarekey1", "Google Chromekey1"]},
    "vivaldi":  {"label": "Vivaldi",         "kind": "chromium",
                 "user_data": _local(r"Vivaldi\User Data"),
                 "cng": ["Google Chromekey1"]},
    "chromium": {"label": "Chromium",        "kind": "chromium",
                 "user_data": _local(r"Chromium\User Data"),
                 "cng": ["Google Chromekey1"]},
    "opera":    {"label": "Opera",           "kind": "chromium",
                 "user_data": _roam(r"Opera Software\Opera Stable"),
                 "cng": ["Google Chromekey1"], "single_profile": True},
    "firefox":  {"label": "Mozilla Firefox", "kind": "firefox",
                 "user_data": _roam(r"Mozilla\Firefox\Profiles")},
}


def chromium_profile_dir(user_data: Path, profile: str, single=False) -> Path:
    return user_data if (single or profile == ".") else user_data / profile


def _chromium_profile_has_data(p: Path) -> bool:
    """Profil dianggap ada bila punya SALAH SATU sinyal data user (bukan
    hanya Login Data). Ini perbaikan utama 'bookmark belum semuanya':
    profil tanpa password tapi punya bookmark/riwayat/tab sebelumnya
    selalu dilewati (mis. Guest Profile)."""
    if not p.is_dir():
        return False
    # Catatan: Preferences/Secure Preferences/Web Data saja BUKAN sinyal
    # (System Profile punya itu tapi bukan data user) — butuh salah satu
    # dari Login Data / Bookmarks / History / Sync / Sessions.
    for fn in ("Login Data", "Bookmarks", "Bookmarks.bak", "History"):
        try:
            if (p / fn).exists():
                return True
        except OSError:
            pass
    try:
        if (p / "Sync Data" / "LevelDB").is_dir():
            return True
    except OSError:
        pass
    try:
        if (p / "Sessions").is_dir() and any((p / "Sessions").iterdir()):
            return True
    except OSError:
        pass
    return False


def find_chromium_profiles(user_data: Path, single=False):
    if single:
        # Opera: profil tunggal = folder user_data itu sendiri.
        return ["Default"] if _chromium_profile_has_data(user_data) else []
    out = []
    if not user_data.exists():
        return out
    # Kandidat eksplisit dulu (Default / Profile N / Guest / System),
    # lalu sapu SEMUA subfolder lain yang punya sinyal data (profil custom).
    candidates = []
    try:
        names = sorted(p.name for p in user_data.iterdir() if p.is_dir())
    except OSError:
        return out
    for n in names:
        if n in ("Default", "Guest Profile", "System Profile") or n.startswith("Profile "):
            candidates.append(n)
    for n in names:
        if n not in candidates:
            p = user_data / n
            # Folder sistem Chromium (bukan profil user) -> lewati.
            if n in ("Crashpad", "BrowserMetrics", "DeferredBrowserMetrics",
                     "Safe Browsing", "ShaderCache", "GrShaderCache", "GraphiteDawnCache",
                     "component_crx_cache", "extensions_crx_cache", "CrashpadMetrics-active.pma"):
                continue
            if _chromium_profile_has_data(p):
                candidates.append(n)
    for n in candidates:
        if _chromium_profile_has_data(user_data / n):
            out.append(n)
    # Urutan stabil: Default dulu, lalu Profile N numerik, lalu lainnya.
    def _sort_key(n):
        if n == "Default":
            return (0, 0, n)
        if n.startswith("Profile "):
            try:
                return (1, int(n.split(" ", 1)[1]), n)
            except ValueError:
                return (1, 9999, n)
        return (2, 0, n)
    return sorted(out, key=_sort_key)


def find_firefox_profiles(profiles_dir: Path):
    out = []
    if not profiles_dir.exists():
        return out
    try:
        entries = sorted(profiles_dir.iterdir())
    except OSError:
        return out
    for p in entries:
        if not p.is_dir():
            continue
        try:
            has = ((p / "logins.json").exists() or (p / "places.sqlite").exists()
                   or (p / "key4.db").exists()
                   or ((p / "bookmarkbackups").is_dir()
                       and any((p / "bookmarkbackups").glob("*.jsonlz4"))))
        except OSError:
            continue
        if has:
            out.append(p.name)
    return out


def detect_browsers():
    """Return {browser_id: {'label','kind','user_data','profiles',...}} utk yg terinstal."""
    found = {}
    for bid, cfg in BROWSERS.items():
        ud = cfg["user_data"]
        if cfg["kind"] == "chromium":
            profs = find_chromium_profiles(ud, cfg.get("single_profile", False))
            # Opera tanpa profil tapi ada file utama tetap dihitung? butuh Login Data
            if profs or (ud / "Local State").exists():
                if profs:
                    found[bid] = {**cfg, "profiles": profs}
        else:
            profs = find_firefox_profiles(ud)
            if profs:
                found[bid] = {**cfg, "profiles": profs}
    return found


# ================================================================= Chromium

def _sqlite_copy_tmp(db_path: Path, suffix=".db"):
    """Salin database SQLite + file -wal/-shm/-journal (data terbaru saat
    browser terbuka ada di sana). Return path temp|None."""
    fd, tmp = tempfile.mkstemp(suffix=suffix)
    os.close(fd)
    try:
        shutil.copy2(db_path, tmp)
        for suf in ("-wal", "-shm", "-journal"):
            src = Path(str(db_path) + suf)
            if src.exists():
                try:
                    shutil.copy2(src, tmp + suf)
                except OSError:
                    pass
        return tmp
    except OSError:
        _sqlite_cleanup_tmp(tmp)
        return None


def _sqlite_cleanup_tmp(tmp):
    if not tmp:
        return
    for f in (tmp, tmp + "-wal", tmp + "-shm", tmp + "-journal"):
        try:
            os.unlink(f)
        except OSError:
            pass


def read_chromium_logins(profile_dir: Path, v10key, v20key, v20fail=None):
    db = profile_dir / "Login Data"
    if not db.exists():
        return [], {"v20_locked": 0}
    tmp = _sqlite_copy_tmp(db)
    if not tmp:
        return [], {"v20_locked": 0}
    try:
        conn = sqlite3.connect(tmp)
        try:
            rows = conn.execute(
                "SELECT origin_url, username_value, password_value FROM logins").fetchall()
        finally:
            conn.close()
    finally:
        _sqlite_cleanup_tmp(tmp)
    res, locked = [], 0
    for url, user, blob in rows:
        if not user and not blob:
            continue
        b = bytes(blob) if blob is not None else b""
        pwd = decrypt_chromium_blob(b, v10key, v20key, v20fail) if b else ""
        if pwd.startswith("<v20"):
            locked += 1
        res.append({"url": url or "", "username": user or "", "password": pwd})
    return res, {"v20_locked": locked}


def flatten_bookmarks(node, folder="", out=None):
    if out is None:
        out = []
    t = node.get("type")
    if t == "url":
        out.append({"title": node.get("name", ""), "url": node.get("url", ""),
                    "folder": folder})
    elif t == "folder":
        name = node.get("name", "")
        fp = f"{folder}/{name}" if folder else name
        for c in node.get("children", []):
            flatten_bookmarks(c, fp, out)
    return out


def _read_bookmarks_file(path: Path, out: list) -> dict | None:
    """Parse 1 file Bookmarks ke list flat. Return raw|None. Tak pernah raise."""
    try:
        if not path.exists():
            return None
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    try:
        for r in raw.get("roots", {}).values():
            if isinstance(r, dict):
                flatten_bookmarks(r, "", out)
    except Exception:
        pass
    return raw


def read_chromium_history(profile_dir: Path, limit=20000):
    """Baca SEMUA riwayat (tabel urls di History sqlite) sebagai cadangan
    bookmark. Profil tanpa file Bookmarks (mis. Profile 6-9) tetap punya
    History + tab sesi sehingga sebelumnya menghasilkan 0 bookmark.
    Folder: 'Riwayat'. Best-effort, tak pernah raise."""
    out = []
    db = profile_dir / "History"
    if not db.exists():
        return out
    tmp = _sqlite_copy_tmp(db)
    if not tmp:
        return out
    try:
        try:
            conn = sqlite3.connect(tmp)
        except sqlite3.Error:
            return out
        try:
            try:
                rows = conn.execute(
                    "SELECT url, title, visit_count FROM urls "
                    "ORDER BY last_visit_time DESC LIMIT ?", (limit,)).fetchall()
            except sqlite3.Error:
                return out
        finally:
            try:
                conn.close()
            except Exception:
                pass
    finally:
        _sqlite_cleanup_tmp(tmp)
    for url, title, _vc in rows:
        if not url or not isinstance(url, str):
            continue
        low = url.lower()
        if not low.startswith(("http://", "https://", "file:///", "chrome://")):
            continue
        if any(b in low for b in _SYNC_URL_BLOCK):
            continue
        out.append({"title": (title or "").strip() or _sync_fallback_title(url),
                    "url": url, "folder": "Riwayat"})
    return out


_SNSS_URL_RE = None


def _snss_url_re():
    global _SNSS_URL_RE
    if _SNSS_URL_RE is None:
        import re
        _SNSS_URL_RE = re.compile(
            rb'https?://[A-Za-z0-9._~:/?#@!$&\'()*+,;=%\-\[\]]{6,400}')
    return _SNSS_URL_RE


def read_chromium_sessions(profile_dir: Path, max_bytes=64 * 1024 * 1024):
    """Baca tab terbuka dari folder Sessions (Session_* / Tabs_* format SNSS)
    + file Current/Last Tabs|Session lawas. Folder: 'Tab Terbuka'.
    Ini data lokal yang TIDAK ada di Sync Data sehingga sebelumnya hilang.
    Best-effort, tak pernah raise."""
    import re
    out = []
    seen = set()
    candidates = []
    sess_dir = profile_dir / "Sessions"
    try:
        if sess_dir.is_dir():
            for f in sorted(sess_dir.iterdir()):
                if f.is_file() and f.name.startswith(("Session_", "Tabs_")):
                    candidates.append(f)
    except OSError:
        pass
    for fn in ("Current Tabs", "Current Session", "Last Tabs", "Last Session"):
        p = profile_dir / fn
        try:
            if p.is_file():
                candidates.append(p)
        except OSError:
            pass
    pat = _snss_url_re()
    total = 0
    for f in candidates:
        try:
            sz = f.stat().st_size
        except OSError:
            continue
        if total + sz > max_bytes or sz <= 0 or sz > 32 * 1024 * 1024:
            continue
        total += sz
        try:
            raw = f.read_bytes()
        except OSError:
            continue
        try:
            hits = pat.findall(raw)
        except Exception:
            continue
        for h in hits:
            try:
                u = h.decode("ascii")
            except UnicodeDecodeError:
                continue
            u = u.rstrip(").,;'\"!")
            if len(u) < 12 or u in seen:
                continue
            low = u.lower()
            if "schemas" in low or "w3.org" in low:
                continue
            if not _sync_url_ok(u):
                continue
            seen.add(u)
            out.append({"title": _sync_fallback_title(u), "url": u,
                        "folder": "Tab Terbuka"})
    return out


def read_chromium_bookmarks(profile_dir: Path):
    """Baca SEMUA sumber bookmark lokal:
      1. Bookmarks + Bookmarks.bak (DIGABUNG + dedup, bukan fallback)
      2. Sync Data LevelDB (reading list / grup tab / sesi / terkirim / sinkronisasi)
      3. History sqlite -> folder 'Riwayat'
      4. Sessions SNSS (Session_*/Tabs_*) -> folder 'Tab Terbuka'
    Return (combined_list, bm_raw). Tak pernah raise untuk sumber 2-4."""
    out, raw = [], None
    # 1. Gabung Bookmarks utama + .bak (salah satunya bisa lebih lengkap).
    seen_local = set()
    for cand in (profile_dir / "Bookmarks", profile_dir / "Bookmarks.bak"):
        tmp_list = []
        got = _read_bookmarks_file(cand, tmp_list)
        if got is not None and raw is None:
            raw = got  # struktur folder HTML memakai file utama
        for b in tmp_list:
            k = (b.get("folder") or "", b.get("url") or "")
            if b.get("url") and k not in seen_local:
                seen_local.add(k)
                out.append(b)
    n_local = len(out)
    # 2. Sync Data.
    try:
        for b in scan_sync_bookmarks(profile_dir):
            k = (b.get("folder") or "", b.get("url") or "")
            if b.get("url") and k not in seen_local:
                seen_local.add(k)
                out.append(b)
    except Exception:
        pass
    # 3+4. Riwayat & sesi lokal (hanya URL yg belum ada agar tak dobel).
    try:
        for b in read_chromium_history(profile_dir):
            k = (b.get("folder") or "", b.get("url") or "")
            if b.get("url") and k not in seen_local:
                seen_local.add(k)
                out.append(b)
    except Exception:
        pass
    try:
        for b in read_chromium_sessions(profile_dir):
            # Tab sesi didedup per-URL saja (judul fallback hostname sama
            # untuk banyak path sehingga dedup (folder,url) kurang tepat
            # bila URL sudah ada dari Sync "Tab Terbuka").
            if not b.get("url"):
                continue
            dup = any(e.get("url") == b["url"] for e in out)
            if not dup:
                out.append(b)
    except Exception:
        pass
    return out, raw


# ================================================================= Firefox

def _firefox_copy_temp(profile_dir: Path, filename: str):
    src = profile_dir / filename
    if not src.exists():
        return None
    fd, tmp = tempfile.mkstemp(suffix="-" + filename)
    os.close(fd)
    try:
        shutil.copy2(src, tmp)
        for suf in ("-wal", "-shm", "-journal"):
            wsrc = Path(str(src) + suf)
            if wsrc.exists():
                try:
                    shutil.copy2(wsrc, tmp + suf)
                except OSError:
                    pass
        return tmp
    except OSError:
        _sqlite_cleanup_tmp(tmp)
        return None


def _lz4_block_decompress(data: bytes) -> bytes:
    """Dekompresi 1 blok LZ4 standar (murni Python, tanpa dependensi).
    Dipakai untuk bookmarkbackups Firefox (*.jsonlz4 = header + blok LZ4)."""
    out = bytearray()
    p, n = 0, len(data)
    while p < n:
        tok = data[p]
        p += 1
        lit = tok >> 4
        if lit == 15:
            while True:
                if p >= n:
                    raise ValueError("lz4: literal terpotong")
                b = data[p]
                p += 1
                lit += b
                if b != 255:
                    break
        if p + lit > n:
            raise ValueError("lz4: literal overrun")
        out += data[p:p + lit]
        p += lit
        if p >= n:
            break  # blok berakhir tepat setelah literal
        if p + 2 > n:
            raise ValueError("lz4: offset terpotong")
        off = data[p] | (data[p + 1] << 8)
        p += 2
        if off == 0 or off > len(out):
            raise ValueError("lz4: offset buruk")
        mlen = (tok & 0x0F) + 4
        if (tok & 0x0F) == 15:
            while True:
                if p >= n:
                    raise ValueError("lz4: match terpotong")
                b = data[p]
                p += 1
                mlen += b
                if b != 255:
                    break
        for _ in range(mlen):
            out.append(out[len(out) - off])
    return bytes(out)


def _read_mozlz4_json(path: Path):
    """Baca *.jsonlz4 Firefox -> objek JSON. Return None bila gagal."""
    try:
        raw = path.read_bytes()
    except OSError:
        return None
    try:
        if raw[:8] != b"mozLz40\x00":
            return None
        dec = _lz4_block_decompress(raw[8:])
        return json.loads(dec.decode("utf-8"))
    except Exception:
        return None


def _flatten_ff_backup_node(node, folder: str, root: str, out: list):
    """Flatten 1 node backup JSON Firefox (rekursif)."""
    if not isinstance(node, dict):
        return
    ntype = node.get("type", "")
    uri = node.get("uri", "") or ""
    title = node.get("title", "") or ""
    if ntype == "text/x-moz-place-separator":
        return
    if ntype == "text/x-moz-place" or (uri and "children" not in node):
        if uri.startswith(("http://", "https://", "file:///", "ftp://", "chrome://", "place:")):
            if not uri.startswith("place:"):
                out.append({"title": title or uri, "url": uri,
                            "folder": folder, "root": root})
        return
    # Folder / container.
    name = title or ""
    sub = f"{folder}/{name}" if folder and name else (name or folder)
    for c in node.get("children", []) or []:
        _flatten_ff_backup_node(c, sub, root, out)


def read_firefox_bookmarkbackups(profile_dir: Path, max_files=6):
    """Baca cadangan otomatis bookmarkbackups/*.jsonlz4 (terbaru dulu).
    Mengembalikan list flat. Best-effort, tak pernah raise."""
    out = []
    bb = profile_dir / "bookmarkbackups"
    try:
        if not bb.is_dir():
            return out
        files = sorted((p for p in bb.glob("*.jsonlz4") if p.is_file()),
                       key=lambda p: p.name, reverse=True)[:max_files]
    except OSError:
        return out
    for f in files:
        data = _read_mozlz4_json(f)
        if not data:
            continue
        roots = []
        if isinstance(data, dict) and isinstance(data.get("children"), list):
            # Format backup: 1 root dengan children = toolbar/menu/unfiled/mobile.
            for top in data["children"]:
                if isinstance(top, dict):
                    roots.append((top.get("title", "") or "", top))
        elif isinstance(data, dict) and isinstance(data.get("roots"), dict):
            for k, v in data["roots"].items():
                if isinstance(v, dict):
                    roots.append((k, v))
        for top_name, top_node in roots:
            low = (top_name or "").lower()
            if "toolbar" in low or "bilah" in low:
                root = "toolbar"
            elif "menu" in low:
                root = "menu"
            elif "mobile" in low:
                root = "mobile"
            elif "tag" in low:
                root = "tags"
            else:
                root = "unfiled"
            _flatten_ff_backup_node(top_node, "", root, out)
    return out


def read_firefox_bookmarks(profile_dir: Path):
    out = []
    seen = set()
    tmp = _firefox_copy_temp(profile_dir, "places.sqlite")
    if tmp:
        try:
            conn = sqlite3.connect(tmp)
            try:
                folders = {i: (p, t or "") for i, p, t in
                           conn.execute("SELECT id, parent, title FROM moz_bookmarks WHERE type = 2").fetchall()}
                rows = conn.execute("""
                    SELECT b.title, p.url, b.parent FROM moz_bookmarks b
                    LEFT JOIN moz_places p ON b.fk = p.id
                    WHERE b.type = 1""").fetchall()
            finally:
                conn.close()
        except sqlite3.Error:
            rows, folders = [], {}
        finally:
            _sqlite_cleanup_tmp(tmp)
        disp = {"menu": "Menu Bookmark", "toolbar": "Bilah Bookmark",
                "unfiled": "Bookmark Lainnya", "mobile": "Mobile", "tags": "Tag"}
        for t, u, parent in rows:
            if not u or u.startswith("place:"):
                continue
            segs, top, cur = [], "", parent
            while cur and cur in folders:
                p, name = folders[cur]
                if p == 1:  # anak langsung root -> nama root (menu/toolbar/...)
                    top = name
                    break
                if name:
                    segs.append(name)
                cur = p
            segs.reverse()
            if top in disp:
                segs = [disp[top]] + segs
            elif top:
                segs = [top] + segs
            k = ("/".join(segs), u)
            if k not in seen:
                seen.add(k)
                out.append({"title": t or "", "url": u, "folder": "/".join(segs),
                            "root": top or "unfiled"})
    # Gabung cadangan otomatis jsonlz4 (bisa lebih lengkap dari places.sqlite).
    try:
        for b in read_firefox_bookmarkbackups(profile_dir):
            k = (b.get("folder") or "", b.get("url") or "")
            if b.get("url") and k not in seen:
                seen.add(k)
                out.append(b)
    except Exception:
        pass
    return out, (True if out or tmp else None)


FF_LOCKED_MSG = "<firefox terkunci: butuh master password / NSS gagal>"


def _firefox_nss_decrypt(profile_dir: Path, b64values):
    """Dekripsi via nss3.dll Firefox. Return dict b64->plaintext (yg gagal = None)."""
    out = {v: None for v in set(b64values)}
    if not b64values:
        return out
    # Siapkan direktori NSS (salinan key db)
    nss_dir = tempfile.mkdtemp(prefix="ff-nss-")
    try:
        for fn in ("key4.db", "cert9.db", "key3.db", "secmod.db"):
            src = profile_dir / fn
            if src.exists():
                try:
                    shutil.copy2(src, os.path.join(nss_dir, fn))
                except OSError:
                    pass
        # Cari nss3.dll
        candidates = []
        for base in (os.environ.get("PROGRAMFILES", r"C:\Program Files"),
                     os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)")):
            candidates.append(os.path.join(base, "Mozilla Firefox", "nss3.dll"))
        candidates.append(os.path.join(os.path.dirname(sys.executable), "nss3.dll"))
        nss_path = next((c for c in candidates if os.path.exists(c)), None)
        if not nss_path:
            return out
        if hasattr(os, "add_dll_directory"):
            try:
                os.add_dll_directory(os.path.dirname(nss_path))
            except Exception:
                pass
        nss = ctypes.CDLL(nss_path)

        class SECItem(ctypes.Structure):
            _fields_ = [("type", ctypes.c_uint), ("data", ctypes.c_char_p),
                        ("len", ctypes.c_uint)]

        nss.NSS_Init.argtypes = [ctypes.c_char_p]
        nss.NSS_Init.restype = ctypes.c_int
        nss.PK11_GetInternalKeySlot.argtypes = []
        nss.PK11_GetInternalKeySlot.restype = ctypes.c_void_p
        nss.PK11_NeedLogin.argtypes = [ctypes.c_void_p]
        nss.PK11_NeedLogin.restype = ctypes.c_int
        nss.PK11_CheckUserPassword.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        nss.PK11_CheckUserPassword.restype = ctypes.c_int
        nss.PK11SDR_Decrypt.argtypes = [ctypes.POINTER(SECItem), ctypes.POINTER(SECItem),
                                        ctypes.c_void_p]
        nss.PK11SDR_Decrypt.restype = ctypes.c_int
        try:
            nss.PK11_FreeSlot.argtypes = [ctypes.c_void_p]
        except AttributeError:
            pass
        try:
            nss.NSS_Shutdown.argtypes = []
        except AttributeError:
            pass

        if nss.NSS_Init(nss_dir.encode("utf-8")) != 0:
            return out
        try:
            slot = nss.PK11_GetInternalKeySlot()
            if not slot:
                return out
            try:
                if nss.PK11_NeedLogin(slot):
                    if nss.PK11_CheckUserPassword(slot, b"") != 0:
                        return out  # master password aktif
                for v in list(out.keys()):
                    try:
                        raw = base64.b64decode(v)
                        buf = ctypes.create_string_buffer(raw, len(raw))
                        inp = SECItem(0, ctypes.cast(buf, ctypes.c_char_p), len(raw))
                        res = SECItem(0, None, 0)
                        if nss.PK11SDR_Decrypt(ctypes.byref(inp), ctypes.byref(res), None) == 0:
                            out[v] = ctypes.string_at(res.data, res.len).decode("utf-8", errors="replace")
                    except Exception:
                        pass
            finally:
                try:
                    nss.PK11_FreeSlot(slot)
                except Exception:
                    pass
        finally:
            try:
                nss.NSS_Shutdown()
            except Exception:
                pass
    except Exception:
        pass
    finally:
        shutil.rmtree(nss_dir, ignore_errors=True)
    return out


def read_firefox_logins(profile_dir: Path):
    f = profile_dir / "logins.json"
    if not f.exists():
        return [], {"locked": 0, "nss": "tanpa logins.json"}
    try:
        data = json.loads(f.read_text(encoding="utf-8"))
    except Exception:
        return [], {"locked": 0, "nss": "logins.json rusak"}
    entries = data.get("logins", [])
    vals = []
    for e in entries:
        vals.append(e.get("encryptedUsername", ""))
        vals.append(e.get("encryptedPassword", ""))
    dec = _firefox_nss_decrypt(profile_dir, [v for v in vals if v])
    res, locked = [], 0
    nss_ok = any(v is not None for v in dec.values())
    for e in entries:
        u = dec.get(e.get("encryptedUsername", ""), None)
        p = dec.get(e.get("encryptedPassword", ""), None)
        if u is None:
            try:
                u = base64.b64decode(e.get("encryptedUsername", "")).decode("utf-8", errors="replace") \
                    if e.get("encryptedUsername") else ""
            except Exception:
                u = FF_LOCKED_MSG
        if p is None:
            p = FF_LOCKED_MSG
            locked += 1
        res.append({"url": e.get("hostname", ""), "username": u or "", "password": p})
    note = "ok via NSS" if nss_ok else ("terkunci (master password?) - file mentah tetap dibackup" if entries else "kosong")
    return res, {"locked": locked, "nss": note}


# ================================================================= Bookmark HTML
# Format Netscape Bookmark-file: langsung bisa di-import
# Chrome/Edge (bookmark manager -> Import) & Firefox (Library -> Import).

# --- Bookmark dari Sync Data (Chrome/Edge/Brave, folder "Sinkronisasi") ---
# File Bookmarks lokal sering kosong karena bookmark hanya hidup di data
# sinkronisasi akun (<profil>/Sync Data/LevelDB/*.ldb). Isinya protobuf;
# dari bukti empiris: BookmarkSpecifics = url field-2 (0x12) + judul field-4
# (0x22); format lama = url field-1 (0x0A) + judul field-3 (0x1A).
# Entri PWA/aplikasi (url field-1 + nama field-2, tanpa judul field-4)
# otomatis tersaring karena judul diwajibkan.

_SYNC_URL_BLOCK = ("safebrowsing", "googleapis.com", "gstatic.com", "gvt1.com",
                   "clients2.google", "update.googleapis", "dl.google.com",
                   "tools.google.com", "redirector.", "oauth", "favicon.ico",
                   "manifest.json", "msedge", "edge.microsoft.com",
                   "mozilla.org", "firefox.com", "chromium.org")
_SYNC_ASSET_SUFFIX = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".css",
                      ".js", ".woff", ".woff2", ".webp", "manifest.json")


def _read_varint(buf: bytes, pos: int):
    val, shift = 0, 0
    while pos < len(buf) and shift < 64:
        b = buf[pos]
        pos += 1
        val |= (b & 0x7F) << shift
        if not b & 0x80:
            return val, pos
        shift += 7
    return None, pos


def _is_printable_text(bs: bytes) -> bool:
    try:
        s = bs.decode("utf-8")
    except UnicodeDecodeError:
        return False
    if not s or len(s) > 300:
        return False
    return all(c.isprintable() for c in s)


# --- Pembaca tabel LevelDB + Snappy (murni Python, tanpa dependensi) ---
# Blok data .ldb sering dikompresi Snappy sehingga scan byte mentah melewatkan
# sebagian besar isi. Footer tabel: 4 varint (meta off/size, index off/size),
# padding, lalu magic 8 byte. Trailer tiap blok: 1 byte tipe (0=mentah,
# 1=snappy) + 4 byte CRC (tidak diverifikasi, best-effort).

_LDB_MAGIC = bytes([0x57, 0xFB, 0x80, 0x8B, 0x24, 0x75, 0x47, 0xDB])


def _snappy_decompress(data: bytes) -> bytes:
    pos, shift, out_len = 0, 0, 0
    while True:
        if pos >= len(data):
            raise ValueError("snappy: preamble pendek")
        b = data[pos]
        pos += 1
        out_len |= (b & 0x7F) << shift
        if not b & 0x80:
            break
        shift += 7
        if shift >= 35:
            raise ValueError("snappy: varint rusak")
    out = bytearray()
    while pos < len(data):
        tag = data[pos]
        pos += 1
        typ = tag & 0x03
        if typ == 0:
            ln = tag >> 2
            if ln < 60:
                ln += 1
            else:
                nb = ln - 59
                if pos + nb > len(data):
                    raise ValueError("snappy: literal pendek")
                ln = int.from_bytes(data[pos:pos + nb], "little") + 1
                pos += nb
            if pos + ln > len(data):
                raise ValueError("snappy: literal overrun")
            out += data[pos:pos + ln]
            pos += ln
        else:
            if typ == 1:
                ln = ((tag >> 2) & 0x7) + 4
                if pos >= len(data):
                    raise ValueError("snappy: copy-1 pendek")
                off = ((tag >> 5) << 8) | data[pos]
                pos += 1
            elif typ == 2:
                ln = (tag >> 2) + 1
                if pos + 2 > len(data):
                    raise ValueError("snappy: copy-2 pendek")
                off = int.from_bytes(data[pos:pos + 2], "little")
                pos += 2
            else:
                ln = (tag >> 2) + 1
                if pos + 4 > len(data):
                    raise ValueError("snappy: copy-4 pendek")
                off = int.from_bytes(data[pos:pos + 4], "little")
                pos += 4
            if off == 0 or off > len(out):
                raise ValueError("snappy: offset buruk")
            for _ in range(ln):
                out.append(out[len(out) - off])
    if len(out) != out_len:
        raise ValueError("snappy: panjang tak cocok")
    return bytes(out)


def _iter_ldb_kv(raw: bytes):
    """Yield (key_tanpa_trailer, value) record hidup dari tabel LevelDB.
    Tombstone (value kosong) dilewati."""
    import struct as _st
    if len(raw) < 48 or raw[-8:] != _LDB_MAGIC:
        raise ValueError("bukan tabel LevelDB")
    pos = len(raw) - 48
    hs = []
    for _ in range(4):
        v, pos = _read_varint(raw, pos)
        if v is None:
            raise ValueError("footer rusak")
        hs.append(v)
    idx_off, idx_size = hs[2], hs[3]
    iblock = raw[idx_off:idx_off + idx_size]
    itrailer = raw[idx_off + idx_size:idx_off + idx_size + 1]
    if itrailer == b"\x01":
        iblock = _snappy_decompress(iblock)
    elif itrailer != b"\x00":
        raise ValueError("index tak dikenal")
    if len(iblock) < 4:
        raise ValueError("blok index rusak")
    (nr,) = _st.unpack("<I", iblock[-4:])
    de = len(iblock) - 4 * (nr + 1)
    if de < 0:
        raise ValueError("index restart rusak")
    p, prev, dhs = 0, b"", []
    while p < de:
        sh, p = _read_varint(iblock, p)
        ns, p = _read_varint(iblock, p)
        vl, p = _read_varint(iblock, p)
        if None in (sh, ns, vl):
            raise ValueError("record index rusak")
        key = prev[:sh] + iblock[p:p + ns]
        p += ns
        val = iblock[p:p + vl]
        p += vl
        prev = key
        bo, q = _read_varint(val, 0)
        bs, q = _read_varint(val, q)
        if None in (bo, bs):
            raise ValueError("handle blok rusak")
        dhs.append((bo, bs))
    for bo, bs in dhs:
        chunk = raw[bo:bo + bs]
        tr = raw[bo + bs:bo + bs + 1]
        if not chunk or not tr:
            continue
        try:
            if tr == b"\x01":
                payload = _snappy_decompress(chunk)
            elif tr == b"\x00":
                payload = chunk
            else:
                continue
        except Exception:
            continue
        if len(payload) < 4:
            continue
        (n2,) = _st.unpack("<I", payload[-4:])
        de2 = len(payload) - 4 * (n2 + 1)
        if de2 < 0:
            continue
        q, pk = 0, b""
        while q < de2:
            sh, q = _read_varint(payload, q)
            ns, q = _read_varint(payload, q)
            vl, q = _read_varint(payload, q)
            if None in (sh, ns, vl):
                break
            k = pk[:sh] + payload[q:q + ns]
            q += ns
            v = payload[q:q + vl]
            q += vl
            pk = k
            if not v:
                continue  # tombstone
            yield _strip_key_trailer(k), v


def _strip_key_trailer(k: bytes) -> bytes:
    if len(k) > 8:
        core = k[:-8]
        try:
            s = core.decode("utf-8")
            if s and all(c.isprintable() or c == " " for c in s):
                return core
        except Exception:
            pass
    return k


def _iter_log_kv(path: Path):
    """Yield (key, value) dari WriteBatch di file .log. Hapus (tag 0) dilewati."""
    import struct as _st
    raw = path.read_bytes()
    n = len(raw)
    off, frag = 0, None
    while off + 7 <= n:
        if off % 32768 + 7 > 32768:
            off += 32768 - (off % 32768)
            continue
        ln = _st.unpack("<H", raw[off + 4:off + 6])[0]
        typ = raw[off + 6]
        data = raw[off + 7:off + 7 + ln]
        if len(data) < ln:
            break
        off += 7 + ln
        if typ == 1:
            batches = [data]
        elif typ == 2:
            frag = [data]
            continue
        elif typ in (3, 4):
            if frag is None:
                continue
            frag.append(data)
            if typ == 4:
                batches = [b"".join(frag)]
                frag = None
            else:
                continue
        else:
            continue
        for rec in batches:
            if len(rec) < 12:
                continue
            (count,) = _st.unpack("<I", rec[8:12])
            p = 12
            for _ in range(min(count, 100000)):
                if p >= len(rec):
                    break
                tag = rec[p]
                p += 1
                kl, p = _read_varint(rec, p)
                if kl is None or p + kl > len(rec):
                    break
                key = rec[p:p + kl]
                p += kl
                if tag == 1:
                    vl, p = _read_varint(rec, p)
                    if vl is None or p + vl > len(rec):
                        break
                    value = rec[p:p + vl]
                    p += vl
                    if value:
                        yield _strip_key_trailer(key), value


def _parse_fields(buf: bytes):
    """Parse pesan protobuf -> {field: [bytes]} (hanya wiretype-2 disimpan).
    Kunci field dibaca sebagai varint penuh (field >= 16 kuncinya 2+ byte).
    Return None bila struktur tak valid."""
    flds, p, n = {}, 0, len(buf)
    while p < n:
        key, p = _read_varint(buf, p)
        if key is None:
            return None
        fn, wt = key >> 3, key & 7
        if wt == 2:
            L, p = _read_varint(buf, p)
            if L is None or L < 0 or p + L > n:
                return None
            flds.setdefault(fn, []).append(buf[p:p + L])
            p += L
        elif wt == 0:
            _, p = _read_varint(buf, p)
        elif wt == 5:
            p += 4
        elif wt == 1:
            p += 8
        else:
            return None
        if p > n:
            return None
    return flds


def _clean_text(bs: bytes, lo=1, hi=200):
    try:
        s = bs.decode("utf-8").strip()
    except Exception:
        return None
    if lo <= len(s) <= hi and all(c.isprintable() for c in s):
        return s
    return None


def _clean_url(raw: bytes):
    if not raw.startswith((b"http://", b"https://", b"file:///", b"chrome://")):
        return None
    try:
        u = raw.decode("ascii")
    except UnicodeDecodeError:
        return None
    return u if all(32 <= ord(c) < 127 for c in u) else None


def _sync_url_ok(url: str) -> bool:
    low = url.lower()
    if any(b in low for b in _SYNC_URL_BLOCK):
        return False
    try:
        from urllib.parse import urlsplit
        path = urlsplit(url).path.lower()
    except Exception:
        path = ""
    return not path.endswith(_SYNC_ASSET_SUFFIX)


def _collect_tabs(buf: bytes, depth=0, acc=None):
    """Kumpulkan (url, judul|None) dari pesan tab di mana pun dalam hierarki
    (grup tab tersimpan, sesi, tab terkirim). Judul hanya dari pesan yang sama
    agar tidak bleed; URL boleh dari sub-pesan (rantai redirect)."""
    if acc is None:
        acc = []
    if depth > 3:
        return acc
    flds = _parse_fields(buf)
    if not flds:
        return acc
    u = None
    for fn in (3, 2, 1):  # tab sesi: url field-2; grup tersimpan: field-3
        for cand in flds.get(fn, []):
            u = _clean_url(cand)
            if u:
                break
        if u:
            break
    if u:
        # Judul format baru di field-4, format lama di field-3.
        # Wajib cek keduanya agar bookmark sync lama tidak hilang.
        t = None
        for fn in (4, 3):
            for cand in flds.get(fn, []):
                # Jangan ambil URL itu sendiri sebagai judul.
                if _clean_url(cand):
                    continue
                t = _clean_text(cand)
                if t and not t.startswith(("http://", "https://", "chrome://", "file:///")):
                    break
            if t:
                break
        acc.append((u, t))
    else:
        for lst in flds.values():
            for v in lst:
                if 16 < len(v) < 20000:
                    _collect_tabs(v, depth + 1, acc)
    return acc


def _sync_fallback_title(url: str) -> str:
    from urllib.parse import urlsplit
    try:
        parts = urlsplit(url)
        if parts.scheme in ("http", "https"):
            return parts.hostname or url
        if parts.scheme == "file":
            return parts.path.rsplit("/", 1)[-1].rsplit("\\", 1)[-1] or url
    except Exception:
        pass
    return url


def scan_sync_bookmarks(profile_dir: Path, max_bytes=256 * 1024 * 1024, max_out=20000):
    """Ekstrak konten simpanan user dari Sync Data LevelDB, per store ASLI:
    - reading_list -> folder "Reading List" (URL dari key, judul dari entity)
    - saved_tab_group -> folder "Grup Tab Tersimpan"
    - sessions -> folder "Tab Terbuka"
    - send_tab_to_self -> folder "Tab Terkirim"
    - bookmarks -> folder "Sinkronisasi" (bila store-nya ada)
    Aplikasi web, ekstensi, dsb. BUKAN simpanan user -> dilewati.
    Best-effort, tak pernah raise. Duplikat digabung, judul terbaik menang."""
    try:
        lv = profile_dir / "Sync Data" / "LevelDB"
        if not lv.is_dir():
            return []
        files = sorted(p for p in lv.iterdir()
                       if p.suffix.lower() in (".ldb", ".log") and p.is_file())
    except OSError:
        return []
    recs = []
    try:
        total = 0
        for f in files:
            try:
                sz = f.stat().st_size
                if total + sz > max_bytes:
                    break
                total += sz
                if f.suffix.lower() == ".ldb":
                    try:
                        recs += [(k, v) for k, v in _iter_ldb_kv(f.read_bytes())]
                    except Exception:
                        pass  # file rusak -> lewati
                else:
                    try:
                        recs += list(_iter_log_kv(f))
                    except Exception:
                        pass
            except OSError:
                continue
    except OSError:
        return []
    merged = {}  # (folder, url) -> judul (terpanjang menang)

    def add(folder, url, title):
        if not url or not title:
            return
        k = (folder, url)
        old = merged.get(k)
        if old is None or len(title) > len(old):
            merged[k] = title

    for key, val in recs:
        try:
            ks = key.decode("utf-8")
        except Exception:
            continue
        if ks.startswith("reading_list-dt-"):
            url = ks[len("reading_list-dt-"):]
            if not _clean_url(url.encode("ascii", errors="ignore")) or not _sync_url_ok(url):
                continue
            t = None
            flds = _parse_fields(val)
            if flds:
                for cand in flds.get(2, []):
                    t = _clean_text(cand)
                    if t and not t.startswith(("http://", "https://", "chrome://", "file:///")):
                        break
                else:
                    t = None
            add("Reading List", url, t or _sync_fallback_title(url))
        elif ks.startswith("saved_tab_group-dt-"):
            for u, t in _collect_tabs(val):
                if _sync_url_ok(u):
                    add("Grup Tab Tersimpan", u, t or _sync_fallback_title(u))
        elif ks.startswith("sessions-dt-"):
            for u, t in _collect_tabs(val):
                if _sync_url_ok(u):
                    add("Tab Terbuka", u, t or _sync_fallback_title(u))
        elif ks.startswith("send_tab_to_self-dt-"):
            for u, t in _collect_tabs(val):
                if _sync_url_ok(u):
                    add("Tab Terkirim", u, t or _sync_fallback_title(u))
        elif ks.startswith("bookmarks-dt-"):
            for u, t in _collect_tabs(val):
                if _sync_url_ok(u):
                    add("Sinkronisasi", u, t or _sync_fallback_title(u))
    return [{"title": t, "url": u, "folder": f}
            for (f, u), t in list(merged.items())[:max_out]]

def _webkit_to_unix_ts(webkit) -> int:
    try:
        return max(0, (int(webkit) - 11644473600000000) // 1000000)
    except (ValueError, TypeError):
        return 0


def _html_node(node, lines):
    t = node.get("type")
    if t == "url" and node.get("url"):
        url = html.escape(node["url"], quote=True)
        title = html.escape(node.get("name", "") or node["url"])
        add = _webkit_to_unix_ts(node.get("date_added", 0))
        lines.append(f'        <DT><A HREF="{url}" ADD_DATE="{add}">{title}</A>')
    elif t == "folder":
        lines.append(f'        <DT><H3>{html.escape(node.get("name", ""))}</H3>')
        lines.append("        <DL><p>")
        for c in node.get("children", []):
            _html_node(c, lines)
        lines.append("        </DL><p>")


def _html_wrap(label: str, body_lines) -> str:
    head = ["<!DOCTYPE NETSCAPE-Bookmark-file-1>",
            '<META HTTP-EQUIV="Content-Type" CONTENT="text/html; charset=UTF-8">',
            f"<TITLE>Bookmarks {html.escape(label)}</TITLE>",
            "<H1>Bookmarks</H1>", "<DL><p>"]
    return "\n".join(head + body_lines + ["</DL><p>"]) + "\n"


def chromium_bookmarks_html(bm_raw, label: str, bookmarks=()) -> str:
    """Format lama satu file (disimpan untuk kompatibilitas)."""
    body = []
    if bm_raw:
        for root in bm_raw.get("roots", {}).values():
            if isinstance(root, dict):
                _html_node(root, body)
    sync = [b for b in bookmarks if b.get("folder") in SYNC_FOLDERS and b.get("url")]
    if sync:
        groups = {}
        for b in sync:
            groups.setdefault(b.get("folder") or "Sinkronisasi", []).append(b)
        for gname in sorted(groups):
            body.append(f"        <DT><H3>{html.escape(gname)}</H3>")
            body.append("        <DL><p>")
            for b in groups[gname]:
                url = html.escape(b["url"], quote=True)
                title = html.escape(b.get("title", "") or b["url"])
                body.append(f'        <DT><A HREF="{url}">{title}</A>')
            body.append("        </DL><p>")
    return _html_wrap(label, body)


def _has_link(lines) -> bool:
    return any("<A HREF=" in ln for ln in lines)


def _raw_bookmark_urls(bm_raw) -> set:
    """Kumpulkan semua URL di file Bookmarks utama (untuk dedup .bak)."""
    urls = set()
    try:
        roots = bm_raw.get("roots", {}) if bm_raw else {}
        stack = [r for r in roots.values() if isinstance(r, dict)]
        while stack:
            nd = stack.pop()
            if nd.get("type") == "url" and nd.get("url"):
                urls.add(nd["url"])
            elif nd.get("type") == "folder":
                stack.extend(c for c in nd.get("children", []) if isinstance(c, dict))
    except Exception:
        pass
    return urls


def chromium_split_html(bm_raw, sync_list, label: str, bar_extra=()):
    """Pecah per root: {'bar': html|None, 'other': html|None}.
    Struktur folder di dalam tiap file dipertahankan (nested DL).
    bar_extra: item flat dari Bookmarks.bak ber-folder 'Bookmarks bar/...'
    (file utama kadang kosong/reset sehingga .bak satu-satunya sumber)."""
    roots = bm_raw.get("roots", {}) if bm_raw else {}
    bar_body, other_body = [], []
    for key, node in roots.items():
        if not isinstance(node, dict):
            continue
        if key == "bookmark_bar":
            _html_node(node, bar_body)
        else:
            _html_node(node, other_body)
    if bar_extra:
        groups: dict = {}
        for b in bar_extra:
            if not b.get("url"):
                continue
            # 'Bookmarks bar/Kerjaan/X' -> subfolder 'Kerjaan/X'.
            segs = [s for s in (b.get("folder") or "").split("/") if s]
            sub = "/".join(segs[1:]) if len(segs) > 1 else ""
            groups.setdefault(sub, []).append(b)
        for sub in sorted(groups):
            if sub:
                bar_body.append(f"        <DT><H3>{html.escape(sub)}</H3>")
                bar_body.append("        <DL><p>")
            for b in groups[sub]:
                url = html.escape(b["url"], quote=True)
                title = html.escape(b.get("title", "") or b["url"])
                bar_body.append(f'        <DT><A HREF="{url}">{title}</A>')
            if sub:
                bar_body.append("        </DL><p>")
    out = {}
    if _has_link(bar_body):
        out["bar"] = _html_wrap(label + " (Bilah bookmark)", bar_body)
    if sync_list:
        groups = {}
        for b in sync_list:
            if b.get("url"):
                groups.setdefault(b.get("folder") or "Sinkronisasi", []).append(b)
        for gname in sorted(groups):
            other_body.append(f"        <DT><H3>{html.escape(gname)}</H3>")
            other_body.append("        <DL><p>")
            for b in groups[gname]:
                url = html.escape(b["url"], quote=True)
                title = html.escape(b.get("title", "") or b["url"])
                other_body.append(f'        <DT><A HREF="{url}">{title}</A>')
            other_body.append("        </DL><p>")
    if _has_link(other_body):
        out["other"] = _html_wrap(label + " (Bookmark lainnya)", other_body)
    return out


def _nest_paths(items):
    """Susun daftar flat ber-'folder' a/b/c menjadi node folder nested."""
    top = {"type": "folder", "name": "", "children": []}
    nodes = {(): top}
    for b in items:
        if not b.get("url"):
            continue
        segs = tuple(s for s in (b.get("folder") or "").split("/") if s)
        for k in range(1, len(segs) + 1):
            if segs[:k] not in nodes:
                nd = {"type": "folder", "name": segs[k - 1], "children": []}
                nodes[segs[:k - 1]]["children"].append(nd)
                nodes[segs[:k]] = nd
        nodes[segs]["children"].append(
            {"type": "url", "name": b.get("title", ""), "url": b["url"]})
    return top["children"]


def firefox_split_html(bookmarks, label: str):
    """Pecah per root: toolbar -> 'bar', sisanya -> 'other'. Folder nested."""
    bar_items = [b for b in bookmarks if b.get("root") == "toolbar"]
    other_items = [b for b in bookmarks if b.get("root") != "toolbar"]
    out = {}
    if bar_items:
        body = []
        for child in _nest_paths(bar_items):
            _html_node(child, body)
        if _has_link(body):
            out["bar"] = _html_wrap(label + " (Bilah bookmark)", body)
    if other_items:
        body = []
        for child in _nest_paths(other_items):
            _html_node(child, body)
        if _has_link(body):
            out["other"] = _html_wrap(label + " (Bookmark lainnya)", body)
    return out


def firefox_bookmarks_html(bookmarks, label: str) -> str:
    """Format lama satu file (disimpan untuk kompatibilitas)."""
    parts = firefox_split_html(bookmarks, label)
    if "other" in parts:
        return parts["other"]
    return next(iter(parts.values()), _html_wrap(label, []))


def unique_path(p: Path) -> Path:
    """Bila path sudah ada, tambah angka (2, 3, ...) seperti contoh user."""
    if not p.exists():
        return p
    stem, suffix = p.stem, p.suffix
    n = 2
    while True:
        q = p.with_name(f"{stem}{n}{suffix}")
        if not q.exists():
            return q
        n += 1


# ================================================================= Export

def safe_name(s: str) -> str:
    return "".join(c if (c.isalnum() or c in " -_") else "_" for c in s).strip() or "profile"


def export_csv(logins, path: Path):
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["name", "url", "username", "password"])
        for r in logins:
            name = r["url"]
            try:
                from urllib.parse import urlparse
                name = urlparse(r["url"]).netloc or r["url"]
            except Exception:
                pass
            w.writerow([name, r["url"], r["username"], r["password"]])


# Nama folder turunan Sync Data + tab sesi lokal (nama store asli, bukan buatan).
# "Riwayat" SENGAJA tidak di sini: riwayat ditulis ke file *-riwayat_*.html
# tersendiri agar tidak membanjiri file bookmark (riwayat bisa belasan ribu
# URL) — tapi tetap ikut terbackup (HARUS SEMUANYA).
SYNC_FOLDERS = ("Reading List", "Grup Tab Tersimpan", "Tab Terbuka",
                "Tab Terkirim", "Sinkronisasi")
RIWAYAT_FOLDER = "Riwayat"


def chromium_history_html(history_items, label: str) -> str | None:
    """Bungkus daftar riwayat menjadi 1 file HTML importable. None bila kosong."""
    items = [b for b in history_items if b.get("url")]
    if not items:
        return None
    body = [f'        <DT><H3>{html.escape(RIWAYAT_FOLDER)}</H3>', "        <DL><p>"]
    for b in items:
        url = html.escape(b["url"], quote=True)
        title = html.escape(b.get("title", "") or b["url"])
        body.append(f'        <DT><A HREF="{url}">{title}</A>')
    body.append("        </DL><p>")
    return _html_wrap(label + " (Riwayat)", body)


def backup_one(browser_id: str, profile: str, out_dir: Path):
    """Backup 1 profil: password -> passwords/*.csv, bookmark -> bookmarks/*.html."""
    cfg = BROWSERS[browser_id]
    label = cfg["label"]
    out_dir.mkdir(parents=True, exist_ok=True)  # buat otomatis bila belum ada
    pw_dir = out_dir / "passwords"
    bm_dir = out_dir / "bookmarks"
    pw_dir.mkdir(parents=True, exist_ok=True)
    bm_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%d_%m_%Y")
    sn = safe_name(profile if profile != "." else "Default")
    written = []

    if cfg["kind"] == "chromium":
        ud = cfg["user_data"]
        v10key, v10err, v20key, v20info = get_chromium_keys(ud, cfg.get("cng", ["Google Chromekey1"]))
        if v20key:
            v20fail = None
        elif is_admin():
            v20fail = f"<v20 gagal: {v20info}>"
        else:
            v20fail = V20_LOCKED_MSG
        pdir = chromium_profile_dir(ud, profile, cfg.get("single_profile", False))
        logins, stats = read_chromium_logins(pdir, v10key, v20key, v20fail)
        bookmarks, bm_raw = read_chromium_bookmarks(pdir)
        p = unique_path(pw_dir / f"{browser_id}-{sn}-passwords_{stamp}.csv")
        export_csv(logins, p)
        written.append(p)
        hist = [b for b in bookmarks if b.get("folder") == RIWAYAT_FOLDER]
        sync_only = [b for b in bookmarks if b.get("folder") in SYNC_FOLDERS]
        # Item lokal dari Bookmarks.bak yang tak ada di file utama (file utama
        # kadang kosong/reset 1KB sementara .bak 100-300KB berisi aslinya).
        raw_urls = _raw_bookmark_urls(bm_raw)
        extra_local = [b for b in bookmarks
                       if b.get("url") and b.get("folder") not in SYNC_FOLDERS
                       and b.get("folder") != RIWAYAT_FOLDER
                       and b.get("url") not in raw_urls]
        bar_extra = [b for b in extra_local
                     if (b.get("folder") or "").split("/")[0] == "Bookmarks bar"]
        other_extra = [b for b in extra_local
                       if (b.get("folder") or "").split("/")[0] != "Bookmarks bar"]
        for rootkey, html_text in chromium_split_html(
                bm_raw, sync_only + other_extra, label, bar_extra).items():
            h = unique_path(bm_dir / f"{browser_id}-{sn}-bookmarks-{rootkey}_{stamp}.html")
            h.write_text(html_text, encoding="utf-8")
            written.append(h)
        hist_html = chromium_history_html(hist, label)
        if hist_html:
            h = unique_path(bm_dir / f"{browser_id}-{sn}-riwayat_{stamp}.html")
            h.write_text(hist_html, encoding="utf-8")
            written.append(h)
        v10s = "ok" if v10key else f"gagal: {v10err}"
        from collections import Counter
        fc = Counter(b.get("folder") or "?" for b in bookmarks if b.get("folder") in SYNC_FOLDERS)
        det = ", ".join(f"{k}: {fc[k]}" for k in sorted(fc)) or "tidak ada"
        n_sync = sum(fc.values())
        n_local = len([b for b in bookmarks
                       if b.get("folder") not in SYNC_FOLDERS and b.get("folder") != RIWAYAT_FOLDER])
        note = (f"v10: {v10s} | v20key: {v20info} | v20_terkunci: {stats['v20_locked']} "
                f"| bookmark lokal: {n_local}, sync [{det}], riwayat: {len(hist)}")
        return logins, bookmarks, written, note

    # ---- firefox ----
    pdir = cfg["user_data"] / profile
    logins, info = read_firefox_logins(pdir)
    bookmarks, _bm = read_firefox_bookmarks(pdir)
    p = unique_path(pw_dir / f"{browser_id}-{sn}-passwords_{stamp}.csv")
    export_csv(logins, p)
    written.append(p)
    for rootkey, html_text in firefox_split_html(bookmarks, label).items():
        h = unique_path(bm_dir / f"{browser_id}-{sn}-bookmarks-{rootkey}_{stamp}.html")
        h.write_text(html_text, encoding="utf-8")
        written.append(h)
    # file mentah agar bisa di-restore (pasangan logins.json + key4.db)
    rawdir = unique_path(pw_dir / f"{browser_id}-{sn}-profilefiles_{stamp}")
    rawdir.mkdir(parents=True, exist_ok=True)
    for fn in ("logins.json", "key4.db", "cert9.db", "places.sqlite"):
        src = pdir / fn
        if src.exists():
            try:
                shutil.copy2(src, rawdir / fn)
            except OSError:
                pass
    bb = pdir / "bookmarkbackups"
    if bb.exists():
        try:
            shutil.copytree(bb, rawdir / "bookmarkbackups", dirs_exist_ok=True)
        except OSError:
            pass
    written.append(rawdir)
    return logins, bookmarks, written, f"NSS: {info['nss']} | terkunci: {info['locked']}"


# ================================================================= Diagnosa v20

def _blob_prefix_counts(profile_dir: Path):
    """Hitung jenis enkripsi password di 1 profil. Return dict prefix->count."""
    db = profile_dir / "Login Data"
    if not db.exists():
        return {}
    fd, tmp = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        shutil.copy2(db, tmp)
        conn = sqlite3.connect(tmp)
        try:
            rows = conn.execute("SELECT password_value FROM logins").fetchall()
        finally:
            conn.close()
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass
    counts = {}
    for (blob,) in rows:
        b = bytes(blob) if blob is not None else b""
        key = b[:3].decode("ascii", errors="replace") if len(b) >= 3 else "(kosong)"
        counts[key] = counts.get(key, 0) + 1
    return counts


def diagnose():
    """Cetak hasil tiap tahap dekripsi v20 agar jelas gagalnya di mana."""
    import getpass
    print(f"Admin: {'YA' if is_admin() else 'TIDAK'}")
    try:
        print(f"User aktif: {getpass.getuser()}")
    except Exception:
        pass
    found = detect_browsers()
    for bid, info in found.items():
        if info["kind"] != "chromium":
            continue
        cfg = BROWSERS[bid]
        print(f"\n===== {info['label']} ({info['user_data']}) =====")
        v10key, v10err, _vk, _vi = get_chromium_keys(
            info["user_data"], cfg.get("cng", ["Google Chromekey1"]))
        print(f"[v10 DPAPI user] : {'OK' if v10key else 'GAGAL: ' + str(v10err)}")
        st = _appbound_steps(info["user_data"], cfg.get("cng", ["Google Chromekey1"]))
        for k in ("localstate", "appbound", "sys", "user", "flag"):
            print(f"[v20 {k:10}] : {st[k]}")
        print(f"[v20 kunci akhir] : {'OK' if st['key'] is not None else 'GAGAL: ' + str(st['error'])}")
        for p in info["profiles"][:3]:
            counts = _blob_prefix_counts(
                chromium_profile_dir(info["user_data"], p, cfg.get("single_profile", False)))
            if counts:
                print(f"[blob {p}] : {counts}")
        if v10key is None and is_admin():
            print(">> Anda admin TAPI kunci v10 gagal dibuka: hampir pasti Anda elevate")
            print("   sebagai AKUN BERBEDA. Jadikan akun harian anggota Administrators,")
            print("   lalu klik kanan -> Run as administrator TANPA memasukkan akun lain.")
    print("\nTempel seluruh output ini jika masih gagal.")


# ================================================================= CLI

def build_parser():
    ap = argparse.ArgumentParser(description="Backup password & bookmark semua browser (data milik sendiri).")
    ap.add_argument("--list-browsers", action="store_true", help="Tampilkan browser & profil terdeteksi.")
    ap.add_argument("--browser", nargs="+", choices=sorted(BROWSERS.keys()), default=None,
                    help="Browser yg dibackup (default: semua yg terdeteksi).")
    ap.add_argument("--profile", default=None, help="Filter 1 nama profil (mis. Default).")
    ap.add_argument("--output", default=str(default_output_dir()),
                    help="Folder output (default: hasil-backup di samping aplikasi, dibuat otomatis).")
    ap.add_argument("--gui", action="store_true")
    ap.add_argument("--show", action="store_true")
    ap.add_argument("--web", action="store_true", help="Buka tampilan web modern (localhost saja).")
    ap.add_argument("--port", type=int, default=12719, help="Port tampilan web (default: 12719).")
    ap.add_argument("--diagnosa", action="store_true",
                    help="Cek tiap tahap dekripsi v20 (jalankan sebagai Administrator).")
    return ap


def mask(s: str) -> str:
    if not s or s.startswith("<"):
        return s
    return s[0] + "*" * max(0, len(s) - 2) + s[-1] if len(s) > 2 else "**"


def main(argv=None):
    args = build_parser().parse_args(argv)
    if getattr(sys, "frozen", False) and len(sys.argv) == 1:
        run_gui(args)  # klik 2x EXE -> langsung GUI desktop
        return 0
    if args.web:
        return run_web(args)
    if args.gui:
        run_gui(args)
        return 0
    if args.diagnosa:
        diagnose()
        return 0
    found = detect_browsers()
    if args.list_browsers:
        if not found:
            print("Tidak ada browser terdeteksi.")
        for bid, info in found.items():
            print(f"{bid} ({info['label']}):")
            for p in info["profiles"]:
                print(f"  - {p}")
        print(f"\n(Admin: {'YA' if is_admin() else 'TIDAK - v20 Chromium butuh Run as administrator'})")
        return 0
    bids = args.browser or sorted(found.keys())
    if not bids:
        print("Tidak ada browser terdeteksi. Install Chrome/Edge/Firefox dulu.", file=sys.stderr)
        return 1
    if not is_admin():
        print("! Tanpa Administrator -> password v20 Chromium akan terkunci.")
        print("  Untuk hasil lengkap: jalankan terminal sebagai Administrator.\n")
    out_dir = Path(args.output)
    for bid in bids:
        if bid not in found:
            print(f"\n--- {bid}: tidak terdeteksi, dilewati ---")
            continue
        info = found[bid]
        print(f"\n===== {info['label']} =====")
        for prof in info["profiles"]:
            if args.profile and prof != args.profile:
                continue
            disp = prof
            print(f"\n--- Profil: {disp} ---")
            try:
                logins, bookmarks, written, note = backup_one(bid, prof, out_dir)
            except Exception as e:
                print(f"Gagal: {e}", file=sys.stderr)
                continue
            ok = sum(1 for r in logins if r["password"] and not r["password"].startswith("<"))
            print(f"Password: {len(logins)} (terbuka: {ok}) | Bookmark: {len(bookmarks)} | {note}")
            for r in logins[:8]:
                print(f"  - {r['url'][:55]:55} | {r['username'][:28]:28} | "
                      f"{r['password'] if args.show else mask(r['password'])}")
            if len(logins) > 8:
                print(f"  ... dan {len(logins) - 8} lainnya.")
            for p in written:
                print(f"  tersimpan: {p}")
            locked = sum(1 for r in logins if r["password"].startswith("<v20"))
            if locked and not is_admin():
                print("  >> v20 terkunci: jalankan sebagai Administrator, atau export manual")
                print("     dari chrome://password-manager/settings -> Export.")
            elif locked:
                print("  >> Sudah admin tapi masih terkunci: jalankan 'python app.py --diagnosa'")
                print("     dan ikuti petunjuknya (seringnya: elevate sebagai akun berbeda).")
    print("\nSelesai. Jaga file hasil (berisi password asli!).")
    return 0


# ================================================================= GUI

def run_gui(_args=None):
    import queue
    import threading
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk

    out_default = Path(_args.output) if _args and _args.output else Path("hasil-backup")

    # Identitas "Arsip": tinta petrol + kuningan kunci di atas abu kabut
    INK, MIST, PAPER, LINE = "#15242C", "#E9EDEF", "#FFFFFF", "#D7DEE1"
    BRASS, BRASS_HI = "#A87F1C", "#C9972B"
    MUTED, CLAY = "#54666D", "#B3402E"
    ADMIN = is_admin()

    root = tk.Tk()
    root.title("Arsip — Backup Password & Bookmark Browser")
    root.geometry("1000x680")
    root.minsize(860, 580)
    root.configure(bg=MIST)

    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass
    style.configure(".", background=MIST, foreground=INK, font=("Segoe UI", 10))
    style.configure("TFrame", background=MIST)
    style.configure("Inner.TFrame", background=PAPER)
    style.configure("TLabel", background=MIST, foreground=INK)
    style.configure("Card.TLabelframe", background=PAPER, bordercolor=LINE)
    style.configure("Card.TLabelframe.Label", background=PAPER, foreground=INK,
                    font=("Segoe UI", 10, "bold"))
    style.configure("TCheckbutton", background=PAPER, foreground=INK, font=("Segoe UI", 10))
    style.configure("TButton", font=("Segoe UI", 10), padding=5)
    style.configure("Treeview", background=PAPER, fieldbackground=PAPER, foreground=INK,
                    rowheight=25, font=("Segoe UI", 9), bordercolor=LINE)
    style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"),
                    background="#F1F4F5", foreground=INK)
    style.map("Treeview", background=[("selected", BRASS_HI)], foreground=[("selected", INK)])
    style.configure("Bar.Horizontal.TProgressbar", background=BRASS_HI,
                    troughcolor=PAPER, bordercolor=LINE)

    # ---- Pita atas ----
    header = tk.Frame(root, bg=INK)
    header.pack(fill="x")
    tk.Label(header, text="Arsip", font=("Georgia", 26, "bold"),
             bg=INK, fg="white").pack(side="left", padx=(18, 10), pady=12)
    tk.Label(header, text="Backup password & bookmark browser, di komputer ini saja.",
             font=("Segoe UI", 10), bg=INK, fg="#B9C6CB").pack(side="left", pady=12)
    tk.Label(header,
             text="Administrator aktif" if ADMIN else "Tanpa administrator — v20 terkunci",
             font=("Segoe UI", 9, "bold"), padx=12, pady=5,
             bg=BRASS_HI if ADMIN else INK, fg=INK if ADMIN else BRASS_HI,
             highlightbackground=BRASS_HI, highlightthickness=0 if ADMIN else 1,
             ).pack(side="right", padx=18, pady=12)

    # ---- Area utama yang bisa diubah ukuran: sumber | hasil ----
    paned = ttk.PanedWindow(root, orient="horizontal")
    paned.pack(fill="both", expand=True, padx=12, pady=12)
    left = tk.Frame(paned, bg=PAPER, highlightbackground=LINE, highlightthickness=1)
    right = tk.Frame(paned, bg=PAPER, highlightbackground=LINE, highlightthickness=1)
    paned.add(left, weight=1)
    paned.add(right, weight=2)

    def card_title(parent, text):
        tk.Label(parent, text=text, font=("Georgia", 15, "bold"),
                 bg=PAPER, fg=INK).pack(anchor="w", padx=14, pady=(12, 0))

    # ---- Kiri: sumber ----
    card_title(left, "Sumber")
    tk.Label(left, text="Centang browser dan profil yang mau dibackup.",
             font=("Segoe UI", 9), bg=PAPER, fg=MUTED).pack(anchor="w", padx=14)
    toolbar = tk.Frame(left, bg=PAPER)
    toolbar.pack(fill="x", padx=10, pady=8)
    btn_all = ttk.Button(toolbar, text="Pilih semua")
    btn_none = ttk.Button(toolbar, text="Kosongkan")
    btn_refresh = ttk.Button(toolbar, text="Muat ulang")
    btn_all.pack(side="left", padx=2)
    btn_none.pack(side="left", padx=2)
    btn_refresh.pack(side="left", padx=2)

    list_host = tk.Frame(left, bg=PAPER)
    list_host.pack(fill="both", expand=True, padx=10, pady=(0, 6))
    canvas = tk.Canvas(list_host, bg=PAPER, highlightthickness=0)
    vsb = ttk.Scrollbar(list_host, orient="vertical", command=canvas.yview)
    canvas.configure(yscrollcommand=vsb.set)
    vsb.pack(side="right", fill="y")
    canvas.pack(side="left", fill="both", expand=True)
    inner = ttk.Frame(canvas, style="Inner.TFrame")
    inner_id = canvas.create_window((0, 0), window=inner, anchor="nw")

    def _fit_inner(_e=None):
        canvas.configure(scrollregion=canvas.bbox("all"))
        canvas.itemconfig(inner_id, width=canvas.winfo_width())

    inner.bind("<Configure>", _fit_inner)
    canvas.bind("<Configure>", _fit_inner)

    def _wheel(e):
        canvas.yview_scroll(-1 if e.delta > 0 else 1, "units")

    canvas.bind("<Enter>", lambda _e: canvas.bind_all("<MouseWheel>", _wheel))
    canvas.bind("<Leave>", lambda _e: canvas.unbind_all("<MouseWheel>"))

    groups = []  # [{bid, all_var, items: [(profile, var)]}]

    def _set_all(g, value):
        for _p, v in g["items"]:
            v.set(value)

    def select_all(value=True):
        for g in groups:
            g["all_var"].set(value)
            _set_all(g, value)

    def refresh():
        for w in inner.winfo_children():
            w.destroy()
        groups.clear()
        found = detect_browsers()
        if not found:
            tk.Label(inner, bg=PAPER, fg=CLAY, justify="left",
                     text="Tidak ada browser terdeteksi.\nInstall Chrome, Edge, atau Firefox lalu tekan Muat ulang."
                     ).pack(anchor="w", padx=6, pady=6)
            return
        for bid, info in found.items():
            all_var = tk.BooleanVar(value=True)
            lf = ttk.LabelFrame(inner, text=info["label"], style="Card.TLabelframe")
            lf.pack(fill="x", padx=4, pady=5)
            g = {"bid": bid, "all_var": all_var, "items": []}
            groups.append(g)
            ttk.Checkbutton(lf, text="Semua profil", variable=all_var,
                            command=lambda g=g: _set_all(g, g["all_var"].get())
                            ).pack(anchor="w", padx=8, pady=(4, 0))
            for p in info["profiles"]:
                v = tk.BooleanVar(value=True)
                g["items"].append((p, v))
                ttk.Checkbutton(lf, text=p, variable=v,
                                command=lambda g=g: g["all_var"].set(
                                    all(vv.get() for _pp, vv in g["items"]))
                                ).pack(anchor="w", padx=24)

    btn_all.configure(command=lambda: select_all(True))
    btn_none.configure(command=lambda: select_all(False))
    btn_refresh.configure(command=refresh)

    # ---- Kanan: hasil ----
    card_title(right, "Hasil")
    count_var = tk.StringVar(value="Belum ada hasil. Pilih sumber, lalu tekan Backup sekarang.")
    tk.Label(right, textvariable=count_var, font=("Segoe UI", 9),
             bg=PAPER, fg=MUTED).pack(anchor="w", padx=14)

    tree_host = tk.Frame(right, bg=PAPER)
    tree_host.pack(fill="both", expand=True, padx=10, pady=8)
    cols = ("browser", "profile", "url", "username", "password")
    heads = {"browser": "Browser", "profile": "Profil", "url": "URL",
             "username": "Username", "password": "Password"}
    widths = {"browser": 120, "profile": 120, "url": 240, "username": 140, "password": 140}
    tree = ttk.Treeview(tree_host, columns=cols, show="headings")
    for c in cols:
        tree.heading(c, text=heads[c])
        tree.column(c, width=widths[c], stretch=True)
    t_vsb = ttk.Scrollbar(tree_host, orient="vertical", command=tree.yview)
    t_hsb = ttk.Scrollbar(tree_host, orient="horizontal", command=tree.xview)
    tree.configure(yscrollcommand=t_vsb.set, xscrollcommand=t_hsb.set)
    tree.grid(row=0, column=0, sticky="nsew")
    t_vsb.grid(row=0, column=1, sticky="ns")
    t_hsb.grid(row=1, column=0, sticky="ew")
    tree_host.grid_rowconfigure(0, weight=1)
    tree_host.grid_columnconfigure(0, weight=1)

    # ---- Bilah aksi bawah ----
    action = tk.Frame(root, bg=PAPER, highlightbackground=LINE, highlightthickness=1)
    action.pack(fill="x", padx=12, pady=(0, 12))
    action.grid_columnconfigure(1, weight=1)
    tk.Label(action, text="Folder output:", bg=PAPER, fg=INK).grid(
        row=0, column=0, padx=(12, 4), pady=10, sticky="w")
    var_out = tk.StringVar(value=str(out_default))
    ttk.Entry(action, textvariable=var_out).grid(row=0, column=1, sticky="ew", pady=10)
    ttk.Button(action, text="Pilih…",
               command=lambda: var_out.set(
                   filedialog.askdirectory(initialdir=var_out.get()) or var_out.get())
               ).grid(row=0, column=2, padx=6, pady=10)
    var_show = tk.BooleanVar(value=False)
    ttk.Checkbutton(action, text="Tampilkan password asli",
                    variable=var_show).grid(row=1, column=0, columnspan=2,
                                            padx=12, sticky="w")
    prog = ttk.Progressbar(action, mode="indeterminate", style="Bar.Horizontal.TProgressbar")
    prog.grid(row=1, column=2, padx=6, sticky="ew")
    prog.grid_remove()
    btn_backup = tk.Button(action, text="BACKUP SEKARANG", font=("Segoe UI", 12, "bold"),
                           bg=BRASS_HI, fg=INK, activebackground=BRASS, activeforeground=INK,
                           relief="flat", padx=28, pady=10, cursor="hand2")
    btn_backup.grid(row=0, column=3, rowspan=2, padx=12, pady=10)

    status = tk.StringVar(value="Siap.")
    tk.Label(root, textvariable=status, font=("Segoe UI", 9),
             bg=MIST, fg=MUTED).pack(anchor="w", padx=14, pady=(0, 10))

    # ---- Backup di thread agar jendela tidak macet ----
    q = queue.Queue()
    running = {"busy": False}

    def worker(sels, out_dir):
        payload = []
        for bid, prof in sels:
            try:
                logins, bookmarks, written, note = backup_one(bid, prof, out_dir)
                payload.append({"ok": True, "bid": bid, "prof": prof, "logins": logins,
                                "n_bm": len(bookmarks),
                                "files": [str(p) for p in written], "note": note})
            except Exception as e:
                payload.append({"ok": False, "bid": bid, "prof": prof, "error": str(e)})
        q.put(payload)

    def finish(payload):
        running["busy"] = False
        prog.stop()
        prog.grid_remove()
        btn_backup.configure(state="normal")
        tree.delete(*tree.get_children())
        total_p = total_b = 0
        notes = []
        show = var_show.get()
        for r in payload:
            if not r["ok"]:
                notes.append(f"{r['bid']}/{r['prof']}: GAGAL {r['error']}")
                continue
            total_p += len(r["logins"])
            total_b += r["n_bm"]
            notes.append(f"{BROWSERS[r['bid']]['label']}/{r['prof']}: "
                         f"{len(r['logins'])} password, {r['n_bm']} bookmark ({r['note']})")
            for row in r["logins"]:
                tree.insert("", "end", values=(
                    BROWSERS[r["bid"]]["label"], r["prof"], row["url"], row["username"],
                    row["password"] if show else mask(row["password"])))
        n_prof = sum(1 for r in payload if r["ok"])
        count_var.set(f"{total_p} password, {total_b} bookmark dari {n_prof} profil.")
        status.set(f"Selesai. File tersimpan di: {var_out.get()}")
        msg = "\n".join(notes[:12])
        if len(notes) > 12:
            msg += f"\n... +{len(notes) - 12} profil"
        msg += f"\n\nFile tersimpan di: {var_out.get()}\nSimpan baik-baik (berisi password asli!)."
        locked = sum(1 for r in payload if r["ok"]
                     for row in r["logins"] if row["password"].startswith("<v20"))
        if locked and not ADMIN:
            msg += ("\n\nSebagian password Chromium v20 terkunci — "
                    "tutup aplikasi, klik kanan → Run as administrator, backup ulang.")
        elif locked:
            msg += ("\n\nSudah admin tapi sebagian password v20 masih terkunci — "
                    "jalankan 'python app.py --diagnosa' di terminal admin dan ikuti petunjuknya.")
        messagebox.showinfo("Selesai", msg)

    def poll():
        try:
            payload = q.get_nowait()
        except queue.Empty:
            root.after(120, poll)
            return
        finish(payload)

    def do_backup():
        if running["busy"]:
            return
        sels = [(g["bid"], p) for g in groups for p, v in g["items"] if v.get()]
        if not sels:
            messagebox.showwarning("Pilih", "Centang minimal 1 browser dan profil dahulu.")
            return
        running["busy"] = True
        btn_backup.configure(state="disabled")
        prog.grid()
        prog.start(12)
        status.set(f"Membackup {len(sels)} profil…")
        threading.Thread(target=worker, args=(sels, Path(var_out.get())), daemon=True).start()
        root.after(120, poll)

    btn_backup.configure(command=do_backup)
    refresh()
    root.mainloop()


def app_base_dir() -> Path:
    """Folder aplikasi: dukung mode frozen (PyInstaller onefile/onedirmode)."""
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS)
    return Path(__file__).resolve().parent


def app_home_dir() -> Path:
    """Folder tempat aplikasi/exe DISIMPAN (untuk output).
    Catatan: exe onefile mengekstrak bundle ke temp (_MEIPASS), jadi untuk
    output harus pakai folder exe-nya, bukan _MEIPASS."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def default_output_dir() -> Path:
    """Lokasi output default: <folder aplikasi>/hasil-backup (dibuat otomatis)."""
    return app_home_dir() / "hasil-backup"


def resolve_web_output(raw) -> Path:
    """Ubah isian 'output' dari web menjadi folder tujuan.

    - Path absolut (mis. ``D:\\Backup\\Arsip``) -> dipakai langsung.
    - Nama / path relatif (mis. ``hasil-backup``) -> di samping aplikasi
      (perilaku lama, tetap kompatibel). Tiap bagian nama dibersihkan
      via safe_name dan ``..`` dibuang agar tak bisa traversal keluar.
    Server hanya listen di 127.0.0.1 sehingga ini setara dengan CLI
    ``--output`` / tombol Pilih di GUI desktop.
    """
    s = str(raw or "").strip() or "hasil-backup"
    s = os.path.expandvars(os.path.expanduser(s))
    p = Path(s)
    if p.is_absolute():
        return p
    parts = []
    for part in p.parts:
        if part in (".", "..", "/", "\\", ""):
            continue
        clean = safe_name(part)
        if clean and clean != "profile":
            parts.append(clean)
        elif clean:
            parts.append(clean)
    if not parts:
        parts = ["hasil-backup"]
    return app_home_dir().joinpath(*parts)


def folder_suggestions() -> list:
    """Lokasi cepat untuk pemilih folder di web (dir + default)."""
    home = app_home_dir()
    default = default_output_dir()
    out = [{"label": "Samping aplikasi", "path": str(default)}]
    profile = os.environ.get("USERPROFILE", "")
    for label, sub in (("Desktop", "Desktop"), ("Dokumen", "Documents"),
                       ("Unduhan", "Downloads")):
        if profile:
            out.append({"label": label, "path": str(Path(profile) / sub / "hasil-backup")})
    # Nama relatif lama tetap didukung -> sediakan juga bentuk pendeknya.
    out.append({"label": "Nama pendek", "path": "hasil-backup"})
    seen, uniq = set(), []
    for s in out:
        if s["path"] not in seen:
            seen.add(s["path"])
            uniq.append(s)
    return uniq


# ================================================================= Web UI (localhost saja)

def run_web(_args=None):
    """Tampilan web modern. Hanya listen di 127.0.0.1 (komputer ini)."""
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from urllib.parse import urlparse

    web_dir = app_base_dir() / "webui"
    if not (web_dir / "index.html").exists():
        print(f"Folder webui tidak ditemukan: {web_dir}", file=sys.stderr)
        return 1
    port = int(getattr(_args, "port", 0) or 12719)
    web_root = web_dir.resolve()

    class Handler(BaseHTTPRequestHandler):
        server_version = "Arsip/1.0"

        def log_message(self, *a):
            pass

        def _send(self, code, body: bytes, ctype: str):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _json(self, obj, code=200):
            self._send(code, json.dumps(obj, ensure_ascii=False).encode("utf-8"),
                       "application/json; charset=utf-8")

        def do_GET(self):
            path = urlparse(self.path).path
            if path == "/api/browsers":
                found = detect_browsers()
                self._json({
                    "admin": is_admin(),
                    "browsers": [{"id": bid, "label": info["label"],
                                  "kind": info["kind"], "profiles": info["profiles"]}
                                  for bid, info in found.items()]})
                return
            if path == "/api/folders":
                self._json({
                    "home": str(app_home_dir()),
                    "default": str(default_output_dir()),
                    "suggestions": folder_suggestions()})
                return
            rel = "index.html" if path in ("/", "") else path.lstrip("/").replace("/", os.sep)
            target = (web_root / rel).resolve()
            if not str(target).startswith(str(web_root)) or not target.is_file():
                self._send(404, "Tidak ditemukan.".encode("utf-8"), "text/plain; charset=utf-8")
                return
            ctype = {".html": "text/html; charset=utf-8",
                     ".css": "text/css; charset=utf-8",
                     ".js": "text/javascript; charset=utf-8"}.get(
                         target.suffix.lower(), "application/octet-stream")
            self._send(200, target.read_bytes(), ctype)

        def do_POST(self):
            if urlparse(self.path).path != "/api/backup":
                self._send(404, "Tidak ditemukan.".encode("utf-8"), "text/plain; charset=utf-8")
                return
            try:
                n = int(self.headers.get("Content-Length", 0))
                body = json.loads(self.rfile.read(n).decode("utf-8") or "{}")
            except Exception:
                self._json({"error": "Data tidak valid (bukan JSON)."}, 400)
                return
            show = bool(body.get("show"))
            out = resolve_web_output(body.get("output"))
            try:
                out.mkdir(parents=True, exist_ok=True)
            except Exception as e:
                self._json({"error": f"Folder output tak bisa dibuat: {out} ({e})"}, 400)
                return
            sels = body.get("selections") or []
            if not sels:
                self._json({"error": "Pilih minimal satu browser dan profil dahulu."}, 400)
                return
            found = detect_browsers()
            results = []
            for s in sels[:60]:
                bid, prof = s.get("browser"), s.get("profile")
                if bid not in BROWSERS or bid not in found or prof not in found[bid]["profiles"]:
                    results.append({"browser": bid, "profile": prof,
                                    "error": "Browser atau profil tidak tersedia."})
                    continue
                try:
                    logins, bookmarks, written, note = backup_one(bid, prof, out)
                    rows = [{"url": r["url"], "username": r["username"],
                             "password": r["password"] if show else mask(r["password"])}
                            for r in logins]
                    results.append({"browser": bid, "label": BROWSERS[bid]["label"],
                                    "profile": prof, "passwords": len(logins),
                                    "bookmarks": len(bookmarks), "note": note,
                                    "files": [str(p) for p in written], "logins": rows})
                except Exception as e:
                    results.append({"browser": bid, "profile": prof,
                                    "error": f"Gagal membackup: {e}"})
            self._json({"output": str(out), "results": results})

    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    url = f"http://127.0.0.1:{srv.server_port}/"
    print(f"Arsip berjalan di {url} (hanya di komputer ini, tutup terminal untuk berhenti)")
    try:
        import webbrowser
        webbrowser.open(url)
    except Exception:
        pass
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
