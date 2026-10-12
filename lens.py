"""Fetch-only replay evidence and clarity lens."""
import hashlib
import json
import re
import time
import urllib.parse
import urllib.request
from datetime import datetime

DID_RE = re.compile(r"did:key:z[A-Za-z0-9]+")
BASE58 = set("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
MAX_BODY = 200000


def parse_jsonl(text):
    records = []
    bad_lines = 0
    for line in text.splitlines():
        s = line.strip()
        if not s:
            continue
        try:
            obj = json.loads(s)
        except ValueError:
            bad_lines += 1
            continue
        records.append(obj)
    return records, bad_lines


def analyze_sequence(records, wait_window=10):
    seqs = []
    for r in records:
        if isinstance(r, dict):
            v = r.get("seq")
            if isinstance(v, int) and v >= 0:
                seqs.append(v)
    total = len(records)
    with_seq = len(seqs)
    if not seqs:
        return {
            "total": total,
            "with_seq": 0,
            "min_seq": None,
            "max_seq": None,
            "gaps": [],
            "duplicates": {},
            "reorder_count": 0,
            "largest_gap": 0,
            "wait_window": wait_window,
            "window_ok": True,
            "coverage": 0.0,
        }
    min_seq = min(seqs)
    max_seq = max(seqs)
    counts = {}
    for s in seqs:
        counts[s] = counts.get(s, 0) + 1
    duplicates = {}
    for k in sorted(counts):
        if counts[k] > 1:
            duplicates[k] = counts[k]
    present = set(seqs)
    gaps = []
    run_start = None
    for n in range(min_seq, max_seq + 1):
        if n not in present:
            if run_start is None:
                run_start = n
        else:
            if run_start is not None:
                gaps.append([run_start, n - 1])
                run_start = None
    if run_start is not None:
        gaps.append([run_start, max_seq])
    reorder_count = 0
    max_seen = seqs[0]
    for s in seqs[1:]:
        if s < max_seen:
            reorder_count += 1
        if s > max_seen:
            max_seen = s
    if gaps:
        largest_gap = max(e - a + 1 for a, e in gaps)
    else:
        largest_gap = 0
    expected = max_seq - min_seq + 1
    if expected > 0:
        coverage = round(len(present) / expected, 4)
    else:
        coverage = 1.0
    return {
        "total": total,
        "with_seq": with_seq,
        "min_seq": min_seq,
        "max_seq": max_seq,
        "gaps": gaps,
        "duplicates": duplicates,
        "reorder_count": reorder_count,
        "largest_gap": largest_gap,
        "wait_window": wait_window,
        "window_ok": largest_gap <= wait_window,
        "coverage": coverage,
    }


def _charset_from_content_type(value):
    if not value:
        return ""
    low = value.lower()
    if "charset=" in low:
        part = low.split("charset=", 1)[1]
        part = part.split(";", 1)[0].strip().strip('"')
        return part
    return ""


def fetch_url_info(url, opener=None, timeout=10):
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return {
            "url": url,
            "ok": False,
            "status": 0,
            "error": "bad-scheme",
            "latency_ms": 0,
            "charset": "",
            "last_modified": "",
            "body_len": 0,
            "sha256": "",
        }
    start = time.monotonic()
    try:
        if opener is not None:
            status, headers, body = opener(url)
        else:
            req = urllib.request.Request(
                url, method="GET", headers={"User-Agent": "technocore-clarity-lens/1.0"}
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                status = resp.status
                headers = dict(resp.headers.items())
                body = resp.read(MAX_BODY)
        elapsed = int((time.monotonic() - start) * 1000)
        low_headers = {}
        for k, v in headers.items():
            low_headers[str(k).lower()] = str(v)
        charset = _charset_from_content_type(low_headers.get("content-type", ""))
        last_modified = low_headers.get("last-modified", "")
        if not isinstance(body, bytes):
            body = bytes(body)
        digest = hashlib.sha256(body).hexdigest()
        ok = isinstance(status, int) and 200 <= status < 400
        return {
            "url": url,
            "ok": ok,
            "status": status,
            "error": "",
            "latency_ms": elapsed,
            "charset": charset,
            "last_modified": last_modified,
            "body_len": len(body),
            "sha256": digest,
        }
    except Exception as exc:
        elapsed = int((time.monotonic() - start) * 1000)
        return {
            "url": url,
            "ok": False,
            "status": 0,
            "error": type(exc).__name__,
            "latency_ms": elapsed,
            "charset": "",
            "last_modified": "",
            "body_len": 0,
            "sha256": "",
        }


def find_dids(text):
    out = []
    for m in DID_RE.finditer(text):
        did = m.group(0)
        tail = did[len("did:key:z"):]
        if len(tail) < 10:
            out.append({"did": did, "ok": False, "reason": "too-short"})
        elif any(c not in BASE58 for c in tail):
            out.append({"did": did, "ok": False, "reason": "bad-chars"})
        else:
            out.append({"did": did, "ok": True, "reason": ""})
    return out


def is_iso_time(value):
    t = value.strip()
    if not t:
        return False
    if t.endswith("Z"):
        t = t[:-1] + "+00:00"
    try:
        datetime.fromisoformat(t)
        return True
    except ValueError:
        return False


def lint_checkin(obj):
    if not isinstance(obj, dict):
        return ["not-an-object"]
    errors = []
    kind = obj.get("type", obj.get("kind", ""))
    if kind != "agent.checkin.v1":
        errors.append("bad-type: expected agent.checkin.v1")
    did = obj.get("did", "")
    if not isinstance(did, str) or not did.startswith("did:key:z"):
        errors.append("bad-did")
    else:
        tail = did[len("did:key:z"):]
        if len(tail) < 10:
            errors.append("bad-did-chars")
        elif any(c not in BASE58 for c in tail):
            errors.append("bad-did-chars")
    seq = obj.get("seq")
    if not isinstance(seq, int) or seq < 0:
        errors.append("bad-seq")
    ts = obj.get("ts", obj.get("time", ""))
    if not isinstance(ts, str) or not is_iso_time(ts):
        errors.append("bad-ts")
    note = obj.get("note", obj.get("message", ""))
    if note is None:
        note = ""
    if not isinstance(note, str):
        errors.append("bad-note-type")
    elif len(note) > 500:
        errors.append("note-too-long")
    return errors


def build_evidence_bundle(title, seq_report, url_infos, checkin_summary, notes=""):
    lines = []
    lines.append("# " + str(title))
    lines.append("")
    lines.append("Public replay evidence. Fetch-only, no secrets.")
    lines.append("")
    lines.append("## Sequence range")
    lines.append("")
    if seq_report.get("min_seq") is None:
        lines.append("No sequence records found.")
    else:
        lines.append("total: " + str(seq_report.get("total")))
        lines.append("with_seq: " + str(seq_report.get("with_seq")))
        rng = str(seq_report.get("min_seq")) + ".." + str(seq_report.get("max_seq"))
        lines.append("range: " + rng)
        lines.append("coverage: " + str(seq_report.get("coverage")))
        lines.append("reorder_count: " + str(seq_report.get("reorder_count")))
        lines.append("largest_gap: " + str(seq_report.get("largest_gap")))
        lines.append("wait_window: " + str(seq_report.get("wait_window")))
        lines.append("window_ok: " + str(seq_report.get("window_ok")))
        gaps = seq_report.get("gaps", [])
        if gaps:
            lines.append("gaps:")
            for a, b in gaps:
                if a == b:
                    lines.append("- missing " + str(a))
                else:
                    lines.append("- missing " + str(a) + ".." + str(b))
        else:
            lines.append("gaps: none")
        dups = seq_report.get("duplicates", {})
        if dups:
            lines.append("duplicates:")
            for k in sorted(dups):
                lines.append("- seq " + str(k) + " x" + str(dups[k]))
        else:
            lines.append("duplicates: none")
    lines.append("")
    lines.append("## Public URL table")
    lines.append("")
    lines.append("| url | status | charset | last-modified | bytes | sha256 |")
    lines.append("| --- | --- | --- | --- | --- | --- |")
    ordered = sorted(url_infos, key=lambda d: d.get("url", ""))
    for u in ordered:
        row = "| " + str(u.get("url", "")) + " | "
        row += str(u.get("status", "")) + " | "
        row += str(u.get("charset", "")) + " | "
        row += str(u.get("last_modified", "")) + " | "
        row += str(u.get("body_len", "")) + " | "
        row += str(u.get("sha256", "")) + " |"
        lines.append(row)
    if not ordered:
        lines.append("| (none) | - | - | - | - | - |")
    lines.append("")
    lines.append("## Check-ins")
    lines.append("")
    if not checkin_summary:
        lines.append("No check-ins reviewed.")
    else:
        for item in checkin_summary:
            name = str(item.get("name", "item"))
            errs = item.get("errors", [])
            if not errs:
                lines.append("- " + name + ": ok")
            else:
                lines.append("- " + name + ": " + ", ".join(errs))
    lines.append("")
    lines.append("## Notes")
    lines.append("")
    if notes:
        lines.append(str(notes))
    else:
        lines.append("Public artifacts only.")
    lines.append("")
    return "\n".join(lines)


def clarity_report(thread_text, glossary=None):
    if glossary is None:
        glossary = set()
    gloss = set(str(w).lower() for w in glossary)
    common = set(["http", "https", "json", "jsonl", "url", "did", "kv", "seq", "get", "wait"])
    text = thread_text.strip()
    if not text:
        return {
            "sentence_count": 0,
            "avg_words": 0.0,
            "long_sentences": [],
            "snippets": [],
            "undefined_terms": [],
        }
    parts = re.split(r"(?<=[.!?])\s+", text)
    sentences = [p.strip() for p in parts if p.strip()]
    long_list = []
    total_words = 0
    for i, s in enumerate(sentences):
        n = len(s.split())
        total_words += n
        if n > 28:
            long_list.append({"index": i, "words": n, "preview": s[:120]})
    if sentences:
        avg = round(total_words / len(sentences), 2)
    else:
        avg = 0.0
    keywords = ("fetch", "curl", "wait", "seq", "cursor", "mirror", "receipt", "long-poll", "longpoll")
    snippets = []
    for line in text.splitlines():
        low = line.lower()
        hit = False
        for kw in keywords:
            if kw in low:
                hit = True
                break
        if hit:
            t = line.strip()[:200]
            if t and t not in snippets:
                snippets.append(t)
    snippets = snippets[:12]
    ticked = re.findall(r"`([^`]+)`", text)
    caps = re.findall(r"\b[A-Z][A-Z0-9_\-]{3,}\b", text)
    candidates = []
    for c in ticked + caps:
        c = c.strip()
        if c and c not in candidates:
            candidates.append(c)
    undefined = []
    for c in candidates:
        low = c.lower()
        if low in gloss or low in common:
            continue
        undefined.append(c)
    undefined = sorted(undefined)[:20]
    return {
        "sentence_count": len(sentences),
        "avg_words": avg,
        "long_sentences": long_list,
        "snippets": snippets,
        "undefined_terms": undefined,
    }
