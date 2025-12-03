import sys
import json
import os
import base64
from datetime import datetime
from urllib.parse import urlparse
import re

# ---------- Config ----------
MEDIA_EXTENSIONS = {
    "png", "jpg", "jpeg", "gif", "ico", "svg", "webp",
    "woff", "woff2", "ttf", "otf", "eot",
    "css", "map",
    "mp4", "mp3", "wav", "webm", "ogg", "avi", "mov", "m4a"
}

MEDIA_MIME_PREFIXES = [
    "image/",
    "audio/",
    "video/",
    "font/",
]

MEDIA_MIME_EXACT = {
    "text/css",
    "application/font-woff",
    "application/font-woff2",
}

STATIC_HTML_MIME = ["text/html"]
STATIC_JS_MIME = [
    "application/javascript",
    "application/x-javascript",
    "text/javascript",
    "application/ecmascript",
    "text/ecmascript",
]

# signature klasik vendor library -> dianggap tidak penting
VENDOR_SIGNATURE_PATTERNS = [
    r"jquery\.org",
    r"jQuery Foundation",
    r"by Google LLC",
    r"Google Inc\.",
    r"Vue\.js is an MIT licensed",
    r"React\.",
    r"AngularJS",
    r"Copyright \(c\) [0-9]{4}",
]

# ukuran threshold (bytes) untuk dianggap besar → diekstrak ke file
# (HAR ZAP kamu pakai Content-Length tipikal, kita gunakan ini saja)
LARGE_STATIC_THRESHOLD = 4096  # 4 KB (silakan adjust)

# ---------- Helpers ----------

def get_extension_from_url(url: str) -> str:
    try:
        path = urlparse(url).path
    except Exception:
        path = url
    if "." not in path:
        return ""
    ext = path.rsplit(".", 1)[-1].lower()
    # hapus query-like bagian jika ada
    ext = ext.split("?")[0].split("#")[0]
    return ext


def is_media_entry(entry: dict) -> bool:
    """
    True jika request/response ini bisa dianggap media/static non-penting
    berdasarkan extension atau mimeType.
    """
    req = entry.get("request", {})
    resp = entry.get("response", {})
    url = req.get("url", "") or ""
    ext = get_extension_from_url(url)

    if ext in MEDIA_EXTENSIONS:
        return True

    content = resp.get("content", {}) or {}
    mime = (content.get("mimeType") or "").lower()

    for p in MEDIA_MIME_PREFIXES:
        if mime.startswith(p):
            return True
    if mime in MEDIA_MIME_EXACT:
        return True

    return False


def get_mime_type(entry: dict) -> str:
    resp = entry.get("response", {})
    content = resp.get("content", {}) or {}
    mime = content.get("mimeType") or ""
    return mime.lower()


def is_static_html(entry: dict) -> bool:
    mime = get_mime_type(entry)
    return any(mime.startswith(mt) for mt in STATIC_HTML_MIME)


def is_static_js(entry: dict) -> bool:
    mime = get_mime_type(entry)
    return any(mt in mime for mt in STATIC_JS_MIME)


def decode_response_body(entry: dict) -> str | None:
    """
    Decode response.content.text yang mungkin base64.
    Return: decoded string (utf-8, errors='replace') atau None jika tidak ada.
    """
    resp = entry.get("response", {})
    content = resp.get("content", {}) or {}
    text = content.get("text")
    if text is None:
        return None

    encoding = (content.get("encoding") or "").lower().strip()

    if encoding == "base64":
        try:
            raw = base64.b64decode(text)
            try:
                return raw.decode("utf-8", errors="replace")
            except Exception:
                # kalau bukan utf-8, masih kita simpan sebagai latin-1 decoded string
                return raw.decode("latin-1", errors="replace")
        except Exception:
            # fallback: treat as plain text
            return text
    else:
        # tidak di-mark base64, treat apa adanya (ZAP kadang pakai langsung)
        return text


def has_vendor_signature(body: str) -> bool:
    lower = body.lower()
    for pat in VENDOR_SIGNATURE_PATTERNS:
        if re.search(pat, lower, flags=re.IGNORECASE):
            return True
    return False


def safe_filename_from_url(url: str, default: str) -> str:
    """
    Ekstrak nama file dari URL, lalu sanitasi untuk filesystem.
    """
    try:
        path = urlparse(url).path
    except Exception:
        path = url

    name = os.path.basename(path) or default

    # fallback kalau masih kosong
    if not name:
        name = default

    # remove query fragments
    name = name.split("?")[0].split("#")[0]

    # sanitize
    name = re.sub(r"[^a-zA-Z0-9_.-]", "_", name)
    return name


def parse_datetime(dt_str: str) -> datetime:
    # ZAP HAR biasanya ISO 8601
    # gunakan fromisoformat jika memungkinkan; fallback ke strptime
    try:
        # handle trailing 'Z'
        if dt_str.endswith("Z"):
            # Python fromisoformat tidak support 'Z', ganti ke +00:00
            return datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
        return datetime.fromisoformat(dt_str)
    except Exception:
        try:
            return datetime.strptime(dt_str, "%Y-%m-%dT%H:%M:%S.%fZ")
        except Exception:
            try:
                return datetime.strptime(dt_str, "%Y-%m-%dT%H:%M:%SZ")
            except Exception:
                # fallback ke epoch jika benar-benar gagal
                return datetime(1970, 1, 1)


# ---------- Core ----------

def process_har(input_har_path: str, har_basename: str):
    # baca HAR
    with open(input_har_path, "r", encoding="utf-8") as f:
        har = json.load(f)

    log = har.get("log", {})
    entries = log.get("entries", [])

    # sort entries by startedDateTime ascending
    entries_with_dt = []
    for e in entries:
        dt = e.get("startedDateTime") or "1970-01-01T00:00:00Z"
        parsed_dt = parse_datetime(dt)
        entries_with_dt.append((parsed_dt, e))

    entries_with_dt.sort(key=lambda x: x[0])
    entries = [e for dt, e in entries_with_dt]

    # siapkan output struktural
    parsed_entries = []

    # folder output
    out_dir = "parsed_hars"
    os.makedirs(out_dir, exist_ok=True)
    static_dir = os.path.join(out_dir, har_basename)
    os.makedirs(static_dir, exist_ok=True)

    for idx, entry in enumerate(entries):
        req = entry.get("request", {}) or {}
        resp = entry.get("response", {}) or {}

        # FILTER media / tidak penting
        if is_media_entry(entry):
            # buang total dari parsed HAR
            continue

        # decode body
        decoded_body = decode_response_body(entry)

        # siapkan copy entry agar tidak ngotorin objek asli terlalu dalam
        new_entry = json.loads(json.dumps(entry))

        # update reference vars
        new_resp = new_entry.get("response", {}) or {}
        new_content = new_resp.get("content", {}) or {}

        mime = get_mime_type(entry)
        content_length_header = None
        for h in new_resp.get("headers", []):
            if h.get("name", "").lower() == "content-length":
                content_length_header = h.get("value")
                break

        size_hint = None
        if content_length_header is not None:
            try:
                size_hint = int(content_length_header)
            except Exception:
                size_hint = None
        if size_hint is None:
            # fallback ke HAR content.size
            content_size = new_content.get("size")
            if isinstance(content_size, int):
                size_hint = content_size

        # static html/js penting?
        is_html = is_static_html(entry)
        is_js = is_static_js(entry)
        is_static_important = is_html or is_js

        extracted_file_path = None

        if decoded_body is not None:
            # cek vendor signature dulu: kalau library umum, treat sebagai tidak penting
            if is_static_important and has_vendor_signature(decoded_body):
                # library umum -> kamu pilih: buang entry atau tetap simpan header?
                # Di sini kita: simpan entry tapi tanpa body, berikan flag.
                new_content["text"] = None
                new_content.pop("encoding", None)
                new_entry["_note"] = new_entry.get("_note") or {}
                if isinstance(new_entry["_note"], dict):
                    new_entry["_note"]["vendor_library_stripped"] = True
                else:
                    new_entry["_note"] = {"vendor_library_stripped": True}

            elif is_static_important and (size_hint is not None and size_hint >= LARGE_STATIC_THRESHOLD):
                # static penting & besar -> ekstrak ke file, kosongkan body
                url = req.get("url", "")
                default_name = f"entry_{idx}"
                filename = safe_filename_from_url(url, default_name)

                ext = "html" if is_html else "js" if is_js else "txt"
                if not filename.lower().endswith(f".{ext}"):
                    filename = f"{filename}.{ext}"

                extracted_file_path = os.path.join(static_dir, filename)

                # tulis file decoded body
                with open(extracted_file_path, "w", encoding="utf-8", errors="replace") as outf:
                    outf.write(decoded_body)

                # kosongkan body di HAR, tapi simpan pointer
                new_content["text"] = None
                new_content.pop("encoding", None)
                new_entry["_extracted_body_file"] = os.path.relpath(extracted_file_path, out_dir)

            else:
                # non-static atau static kecil: tetap simpan decoded ke HAR
                new_content["text"] = decoded_body
                # encoding sudah tidak base64 lagi
                new_content.pop("encoding", None)

        # pastikan perubahan content ditulis balik
        new_resp["content"] = new_content
        new_entry["response"] = new_resp

        parsed_entries.append(new_entry)

    # simpan HAR yang sudah diproses
    har["log"]["entries"] = parsed_entries

    output_path = os.path.join(out_dir, f"{har_basename}.json")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(har, f, indent=2, ensure_ascii=False)

    print(f"[+] Parsed HAR written to: {output_path}")
    print(f"[+] Extracted static files (if any) in: {static_dir}")


def main():
    if len(sys.argv) != 2:
        print("Usage: python parser.py <har_basename>")
        print("Example: python parser.py juice_shop")
        sys.exit(1)

    har_basename = sys.argv[1]
    input_har = f"hars/{har_basename}.har"

    if not os.path.exists(input_har):
        print(f"[-] HAR file not found: {input_har}")
        sys.exit(1)

    process_har(input_har, har_basename)


if __name__ == "__main__":
    main()