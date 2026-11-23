"""Record the Fastly route matchers without pretending the spike implements them."""
import json
import hashlib
import re
from pathlib import Path

root = Path(__file__).resolve().parents[2]
source = (root / "src/main.rs").read_text()
start = source.index("fn route_request(")
match_start = source.index("match (", start)
pre_match = []
prefix_lines = source[start:match_start].splitlines()
prefix_offset = source[:start].count("\n") + 1
for number, line in enumerate(prefix_lines, prefix_offset):
    if any(marker in line for marker in ("match b2_cdn::route", "match canary::route", 'path.strip_prefix("/api/bunny-playback/")')):
        pre_match.append({"source_line": number, "matcher": line.strip(), "parity": "not established"})
end = source.index("\nfn ", match_start)
lines = source[match_start:end].splitlines()
offset = source[:match_start].count("\n") + 1
routes = []
pending = []
for number, line in enumerate(lines, offset):
    if re.match(r"\s*\((?:Method::|_)", line):
        pending = [line.strip()]
        first = number
    elif pending:
        pending.append(line.strip())
    if pending and "=>" in line:
        matcher = " ".join(pending).split("=>")[0].strip()
        routes.append({"source_line": first, "matcher": matcher, "parity": "not established"})
        pending = []

(Path(__file__).parent / "routes.json").write_text(
    json.dumps({"source": "src/main.rs:route_request", "source_sha256": hashlib.sha256(source.encode()).hexdigest(), "pre_match_dispatches": pre_match, "routes": routes}, indent=2) + "\n"
)
print(f"Recorded {len(routes)} canonical route matchers; no parity claims inferred.")
