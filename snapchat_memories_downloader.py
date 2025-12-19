"""
Snapchat Memories Downloader (Organized + No Duplicates)

What it does:
- Parses Snapchat's export file "memories_history.html" and extracts download URLs from:
    onclick="downloadMemories('https://...')"
- Downloads oldest -> newest
- Prevents duplicates using a stable key (mid/sid) instead of the full URL (sig changes)
- Extra safety: if the exact same file bytes appear again, it moves the copy into "Snapchat Dupes" (never deletes)
- Organizes output into:
    OUT_DIR/Images/<YEAR>/<MONTH_NAME>/
    OUT_DIR/Videos/<YEAR>/<MONTH_NAME>/
- Uses date-based filenames from the export table:
    YYYY-MM-DD_HH-MM-SS(.jpg/.mp4)
- Resume support via .part files
- No quality loss and no metadata writing

How to use:
  python snapchat_memories_downloader.py --html "PATH_TO/memories_history.html" --out "PATH_TO_OUTPUT_DIR"
"""

from __future__ import annotations

import os
import re
import json
import time
import hashlib
import calendar
import argparse
from datetime import datetime, timezone
from urllib.parse import urlparse, parse_qs

import requests
from bs4 import BeautifulSoup


# ===================== DEFAULTS (PLACEHOLDERS) =====================
# You can edit these, but it's recommended to pass --html and --out instead.

DEFAULT_HTML_PATH = r"PATH_TO\memories_history.html"
DEFAULT_OUT_DIR   = r"PATH_TO\Snapchat Memories Output"

STATE_FILENAME = "_state.json"
DUPES_FOLDERNAME = "Snapchat Dupes"


# ===================== SETTINGS DEFAULTS =====================
DEFAULT_RETRIES = 6
DEFAULT_TIMEOUT = 60
DEFAULT_CHUNK_SIZE = 1024 * 256  # 256KB
DEFAULT_SLEEP_BETWEEN = 0.15


# ===================== HELPERS =====================

def parse_utc_dt(text: str) -> datetime:
    # Example: "2025-12-06 10:51:22 UTC"
    text = text.strip().replace(" UTC", "")
    return datetime.strptime(text, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)

def sanitize_filename(name: str) -> str:
    name = re.sub(r'[<>:"/\\|?*\x00-\x1F]', "_", name).strip()
    return name[:180] if len(name) > 180 else name

def stable_key_from_url(url: str) -> str:
    """
    Build a stable key that survives expiring signatures (sig=...).
    Prefer mid, then sid. If neither exists, remove sig and use remaining query.
    """
    q = parse_qs(urlparse(url).query)

    mid = (q.get("mid", [None])[0] or "").strip()
    sid = (q.get("sid", [None])[0] or "").strip()
    if mid:
        return f"mid:{mid}"
    if sid:
        return f"sid:{sid}"

    q.pop("sig", None)
    parts = [f"{k}={v[0]}" for k, v in sorted(q.items()) if v]
    return "q:" + "&".join(parts) if parts else "url:" + url

def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def load_state(state_path: str) -> set[str]:
    if os.path.exists(state_path):
        with open(state_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return set(data.get("downloaded_keys", []))
    return set()

def save_state(state_path: str, keys: set[str]) -> None:
    with open(state_path, "w", encoding="utf-8") as f:
        json.dump({"downloaded_keys": sorted(keys)}, f, indent=2)

def extract_url_from_onclick(onclick: str) -> str | None:
    # onclick="downloadMemories('https://....', this, true); return false;"
    if not onclick:
        return None
    m = re.search(r"downloadMemories\(\s*'([^']+)'", onclick)
    return m.group(1).strip() if m else None

def extract_items(html_path: str):
    """
    Returns list of dicts:
    { dt, url, key, kind, ext }
    """
    with open(html_path, "r", encoding="utf-8", errors="ignore") as f:
        soup = BeautifulSoup(f.read(), "html.parser")

    items = []
    for tr in soup.find_all("tr"):
        tds = tr.find_all("td")
        if len(tds) < 3:
            continue

        date_text = tds[0].get_text(" ", strip=True)
        media_type = tds[1].get_text(" ", strip=True).lower()

        a = tr.find("a", onclick=True)
        if not a:
            continue

        url = extract_url_from_onclick(a.get("onclick", ""))
        if not url or not url.startswith("http"):
            continue

        try:
            dt = parse_utc_dt(date_text)
        except Exception:
            continue

        if media_type == "video":
            kind = "Videos"
            ext = ".mp4"
        else:
            # Treat everything else as image (matches Snapchat table)
            kind = "Images"
            ext = ".jpg"

        key = stable_key_from_url(url)
        items.append({"dt": dt, "url": url, "key": key, "kind": kind, "ext": ext})

    # Oldest -> newest
    items.sort(key=lambda x: x["dt"])
    return items

def download_with_resume(
    session: requests.Session,
    url: str,
    dest_path: str,
    timeout: int,
    chunk_size: int
) -> bool:
    part = dest_path + ".part"
    resume_pos = os.path.getsize(part) if os.path.exists(part) else 0

    headers = {}
    if resume_pos > 0:
        headers["Range"] = f"bytes={resume_pos}-"

    with session.get(url, stream=True, timeout=timeout, headers=headers, allow_redirects=True) as r:
        if r.status_code in (401, 403):
            return False
        r.raise_for_status()

        mode = "ab" if resume_pos > 0 else "wb"
        with open(part, mode) as f:
            for chunk in r.iter_content(chunk_size=chunk_size):
                if chunk:
                    f.write(chunk)

    os.replace(part, dest_path)
    return True

def ensure_dirs(out_dir: str, dupes_dir: str):
    os.makedirs(out_dir, exist_ok=True)
    os.makedirs(dupes_dir, exist_ok=True)
    os.makedirs(os.path.join(out_dir, "Images"), exist_ok=True)
    os.makedirs(os.path.join(out_dir, "Videos"), exist_ok=True)

def unique_dest_path(target_dir: str, base: str, ext: str) -> str:
    fname = sanitize_filename(base + ext)
    dest = os.path.join(target_dir, fname)
    counter = 1
    while os.path.exists(dest) or os.path.exists(dest + ".part"):
        fname = sanitize_filename(f"{base}_{counter:02d}{ext}")
        dest = os.path.join(target_dir, fname)
        counter += 1
    return dest


# ===================== RUNNER =====================

def run(
    html_path: str,
    out_dir: str,
    retries: int,
    timeout: int,
    chunk_size: int,
    sleep_between: float
) -> None:
    # Guardrails for users who forget to set paths:
    if "PATH_TO" in html_path or not html_path.lower().endswith(".html"):
        raise SystemExit(
            "ERROR: Please provide a valid --html path to memories_history.html.\n\n"
            "Example:\n"
            "  python snapchat_memories_downloader.py --html \"C:\\path\\to\\memories_history.html\" --out \"C:\\output\""
        )

    state_path = os.path.join(out_dir, STATE_FILENAME)
    dupes_dir = os.path.join(out_dir, DUPES_FOLDERNAME)

    ensure_dirs(out_dir, dupes_dir)

    items = extract_items(html_path)
    if not items:
        print("No downloadable items found. Ensure memories_history.html contains downloadMemories('https...').")
        return

    downloaded_keys = load_state(state_path)
    seen_hashes: set[str] = set()

    session = requests.Session()

    total = len(items)
    print(f"Found {total} memories. Downloading oldest -> newest.")
    print(f"HTML:   {html_path}")
    print(f"Output: {out_dir}\n")

    successes = 0
    skipped = 0
    failed = 0
    moved_dupes = 0

    for idx, it in enumerate(items, start=1):
        key = it["key"]
        if key in downloaded_keys:
            skipped += 1
            continue

        dt = it["dt"]
        year = str(dt.year)
        month = calendar.month_name[dt.month]  # e.g., "January"
        kind = it["kind"]
        ext = it["ext"]

        target_dir = os.path.join(out_dir, kind, year, month)
        os.makedirs(target_dir, exist_ok=True)

        base = dt.strftime("%Y-%m-%d_%H-%M-%S")
        dest = unique_dest_path(target_dir, base, ext)

        print(f"[{idx}/{total}] {kind}/{year}/{month}/{os.path.basename(dest)}")

        ok = False
        for attempt in range(retries):
            try:
                ok = download_with_resume(session, it["url"], dest, timeout=timeout, chunk_size=chunk_size)
                if ok:
                    break
            except Exception:
                ok = False
            time.sleep(1 + attempt)

        if not ok:
            failed += 1
            print("   ❌ Failed (often expired link / 401/403).")
            continue

        # Byte-identical dedupe safety net (never delete, only move)
        try:
            h = sha256_file(dest)
            if h in seen_hashes:
                dupe_dest = os.path.join(dupes_dir, os.path.basename(dest))

                dupe_counter = 1
                root, ext2 = os.path.splitext(dupe_dest)
                while os.path.exists(dupe_dest):
                    dupe_dest = f"{root}_{dupe_counter:02d}{ext2}"
                    dupe_counter += 1

                os.replace(dest, dupe_dest)
                moved_dupes += 1
                print("   ↪ Moved exact duplicate to Snapchat Dupes.")
            else:
                seen_hashes.add(h)
        except Exception:
            pass

        downloaded_keys.add(key)
        successes += 1

        if successes % 25 == 0:
            save_state(state_path, downloaded_keys)

        time.sleep(sleep_between)

    save_state(state_path, downloaded_keys)

    print("\nDONE.")
    print(f"✅ Downloaded this run: {successes}")
    print(f"⏭️ Skipped (already in {STATE_FILENAME}): {skipped}")
    print(f"❌ Failed: {failed}")
    print(f"📦 Exact duplicates moved to '{DUPES_FOLDERNAME}': {moved_dupes}")

    if failed:
        print("\nTip: If many fail with 401/403, generate a NEW Snapchat export and rerun.")
        print("The script will continue where it left off thanks to the state file.")


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Download Snapchat Memories from memories_history.html (organized + deduped)."
    )
    p.add_argument("--html", default=DEFAULT_HTML_PATH,
                   help="Path to memories_history.html from your Snapchat export.")
    p.add_argument("--out", default=DEFAULT_OUT_DIR,
                   help="Output directory where Images/ and Videos/ will be created.")
    p.add_argument("--retries", type=int, default=DEFAULT_RETRIES,
                   help="Retries per file (default: 6).")
    p.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                   help="HTTP timeout seconds (default: 60).")
    p.add_argument("--chunk-size", type=int, default=DEFAULT_CHUNK_SIZE,
                   help="Download chunk size in bytes (default: 262144).")
    p.add_argument("--sleep", type=float, default=DEFAULT_SLEEP_BETWEEN,
                   help="Sleep between downloads in seconds (default: 0.15).")
    return p


if __name__ == "__main__":
    args = build_arg_parser().parse_args()
    run(
        html_path=args.html,
        out_dir=args.out,
        retries=args.retries,
        timeout=args.timeout,
        chunk_size=args.chunk_size,
        sleep_between=args.sleep,
    )
