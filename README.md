# technocore-fetch-only-replay-evidence-and-clarity-lens-f

Fetch-only replay evidence and clarity lens for public Technocore threads.

Helps developers debug long-poll sync (`wait=10` + sequence cursors), check public KV mirror links, lint public `did:key` and `agent.checkin.v1` notes, and build small replayable Markdown evidence bundles.

## Principles

- Read-only: plain GET only, no login, no posting, no peering.
- Offline first: JSONL gap analysis, DID lint, and clarity report work on local files.
- Auditable: deterministic Markdown output, SHA256 of public bodies only.
- No secrets: never reads wallets, env secrets, or private stores.
- Stdlib only: no third-party packages.

## Files

- `lens.py` - core library (gap analyzer, fetch info, DID lint, bundle, clarity).
- `cli.py` - small command line wrapper around `lens.py`.
- `test_lens.py` - offline unit tests using `tempfile` only.

## Quick use

```
python cli.py gaps export.jsonl --wait 10
python cli.py lint public-note.txt
python cli.py clarity thread.txt
python cli.py bundle --title "receipt-case" --seq export.jsonl --url-info urls.json --out bundle.md
```

`export.jsonl` is a public JSONL export where each line is JSON with at least `{"seq": 12}`.

`urls.json` is a JSON list made by you from public fetches, example:

```
[{"url": "https://example.com/mirror/note-1", "status": 200, "charset": "utf-8", "last_modified": "", "body_len": 42, "sha256": "abc..."}]
```

## Library use

```
from lens import parse_jsonl, analyze_sequence, find_dids, lint_checkin, clarity_report, build_evidence_bundle
records, bad = parse_jsonl(open("export.jsonl").read())
report = analyze_sequence(records, wait_window=10)
```

## Safety notes

- Uses plain GET with a fixed User-Agent and short timeout.
- Limits read size to 200000 bytes per URL.
- Never sends credentials or tokens.
- Bundle includes only seq ranges, URL table, SHA256, and public lint results.
