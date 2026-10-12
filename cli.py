"""Small command line wrapper for lens.py."""
import argparse
import json
import pathlib
import lens


def read_text(path):
    return pathlib.Path(path).read_text(encoding="utf-8")


def cmd_gaps(args):
    text = read_text(args.jsonl)
    records, bad = lens.parse_jsonl(text)
    report = lens.analyze_sequence(records, wait_window=args.wait)
    report["bad_lines"] = bad
    print(json.dumps(report, indent=2, sort_keys=True))


def cmd_lint(args):
    text = read_text(args.input)
    dids = lens.find_dids(text)
    print("DIDs found: " + str(len(dids)))
    for d in dids:
        print(str(d["did"]) + " ok=" + str(d["ok"]) + " " + d["reason"])
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            errs = lens.lint_checkin(obj)
            if not errs:
                print("checkin: ok")
            else:
                print("checkin errors: " + ", ".join(errs))
    except ValueError:
        print("checkin: not a JSON object, DID scan only")


def cmd_clarity(args):
    text = read_text(args.input)
    rep = lens.clarity_report(text)
    print(json.dumps(rep, indent=2, sort_keys=True))


def cmd_bundle(args):
    seq_text = read_text(args.seq)
    records, bad = lens.parse_jsonl(seq_text)
    seq_report = lens.analyze_sequence(records, wait_window=args.wait)
    seq_report["bad_lines"] = bad
    url_infos = []
    if args.url_info:
        raw = read_text(args.url_info)
        loaded = json.loads(raw)
        if isinstance(loaded, list):
            for item in loaded:
                if isinstance(item, dict) and "url" in item:
                    url_infos.append({
                        "url": str(item.get("url", "")),
                        "status": item.get("status", 0),
                        "charset": str(item.get("charset", "")),
                        "last_modified": str(item.get("last_modified", "")),
                        "body_len": item.get("body_len", 0),
                        "sha256": str(item.get("sha256", "")),
                    })
    summary = []
    if args.checkins:
        for part in args.checkins.split(";;"):
            name = part.strip()[:40]
            if not name:
                continue
            try:
                obj = json.loads(part)
                errs = lens.lint_checkin(obj)
            except ValueError:
                errs = ["not-json"]
                obj = None
            summary.append({"name": name[:20], "errors": errs})
    bundle = lens.build_evidence_bundle(args.title, seq_report, url_infos, summary, args.notes)
    pathlib.Path(args.out).write_text(bundle, encoding="utf-8")
    print("wrote " + args.out)


def build_parser():
    p = argparse.ArgumentParser(description="Fetch-only replay evidence lens")
    sub = p.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("gaps", help="analyze JSONL seq gaps")
    g.add_argument("jsonl")
    g.add_argument("--wait", type=int, default=10)
    g.set_defaults(func=cmd_gaps)
    l = sub.add_parser("lint", help="lint DIDs and checkin JSON")
    l.add_argument("input")
    l.set_defaults(func=cmd_lint)
    c = sub.add_parser("clarity", help="clarity report for thread text")
    c.add_argument("input")
    c.set_defaults(func=cmd_clarity)
    b = sub.add_parser("bundle", help="build Markdown bundle")
    b.add_argument("--title", default="replay-evidence")
    b.add_argument("--seq", required=True)
    b.add_argument("--url-info", default="")
    b.add_argument("--checkins", default="")
    b.add_argument("--notes", default="")
    b.add_argument("--out", required=True)
    b.add_argument("--wait", type=int, default=10)
    b.set_defaults(func=cmd_bundle)
    return p


def main():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
