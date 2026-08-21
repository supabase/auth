#!/usr/bin/env python3

"""Extracts the JSON examples of the SCIM RFCs into golden files.

The goldens let scimtest check an implementation against the specification's own
documents. See internal/api/scim/scimtest for how they are used.

The section line numbers below are keyed to the published RFC text. An RFC is
immutable once published, so those numbers are stable, and the digest of the
source is pinned to catch a reflowed or truncated copy rather than silently
extracting nonsense from it.

Usage:
    hack/extract-scim-goldens.py [--rfc-dir DIR] [--out DIR] [--check]

The RFC text is looked for in --rfc-dir, then $RFC_DIR, then ~/.local/share/rfc,
and is downloaded from rfc-editor.org if it is in none of them. --check reports
whether the goldens on disk are what the RFC yields, without writing them.
"""

import argparse
import hashlib
import json
import os
import re
import sys
import urllib.request

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
DEFAULT_OUT = os.path.join(REPO, "internal/api/scim/scimtest/testdata")

# The page headers and footers of an RFC, which fall in the middle of an example.
FURNITURE = re.compile(r"^(RFC \d{4}\s|Hunt, et al\.\s|\f)")

RFCS = {
    "rfc7643": {
        "digest": "df799c112a3fa5be3c0fe054c08b1f4eb5d07590c4c8343a014c4537bf638ae3",
        # section, first line, last line, name of each JSON block in that range
        "sections": [
            ("8.1", 1857, 1910, ["minimal_user"]),
            ("8.2", 1911, 2134, ["full_user"]),
            ("8.3", 2135, 2358, ["enterprise_user"]),
            ("8.4", 2359, 2414, ["group"]),
            ("8.5", 2415, 2526, ["service_provider_configuration"]),
            ("8.6", 2527, 2582, ["resource_types"]),
            ("8.7.1", 2590, 4094, ["resource_schemas"]),
            ("8.7.2", 4095, 5102, ["service_provider_schemas"]),
        ],
    },
}


def source(rfc, rfc_dir):
    """Read the RFC text, downloading it if it is not on disk, and verify that
    it is the published text the line numbers were taken from."""
    path = os.path.join(rfc_dir, rfc + ".txt") if rfc_dir else None

    if path and os.path.exists(path):
        text = open(path, encoding="utf-8").read()
    else:
        url = "https://www.rfc-editor.org/rfc/%s.txt" % rfc
        print("fetching %s" % url)
        text = urllib.request.urlopen(url).read().decode("utf-8")

    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    if digest != RFCS[rfc]["digest"]:
        raise SystemExit(
            "%s is not the published text this script was written against\n"
            "  expected sha256 %s\n  found    sha256 %s" % (rfc, RFCS[rfc]["digest"], digest)
        )

    # split on "\n" alone: str.splitlines also breaks on the form feeds the RFC
    # uses for page breaks, which would shift every line number
    return text.split("\n")


def blocks(text):
    """Yield the balanced JSON blocks of text, tracking string state so that a
    brace inside a string does not confuse the depth count."""
    out, i, n = [], 0, len(text)
    while i < n:
        if text[i] not in "[{":
            i += 1
            continue

        depth, in_str, esc, start = 0, False, False, i
        while i < n:
            c = text[i]
            if in_str:
                if esc:
                    esc = False
                elif c == "\\":
                    esc = True
                elif c == '"':
                    in_str = False
            elif c == '"':
                in_str = True
            elif c in "[{":
                depth += 1
            elif c in "]}":
                depth -= 1
                if depth == 0:
                    out.append(text[start:i + 1])
                    i += 1
                    break
            i += 1
        else:
            break
    return out


def join_wrapped(literal):
    """Join the raw newlines the RFC introduced inside one JSON string literal.

    In prose the line break stands in for a space. In a continuous token, such
    as the base64 of a certificate, it stands for nothing. A literal that holds
    no space once joined tight was a token, so it is joined tight."""
    if "\n" not in literal:
        return literal

    parts = [p.strip() for p in literal.split("\n")]
    tight = "".join(parts)
    if " " not in tight:
        return tight

    return re.sub(r"\s+", " ", " ".join(p for p in parts if p))


def unwrap_strings(block):
    """Rejoin every string literal the RFC wrapped across lines. No JSON parser
    accepts a raw newline inside a string, so this is what makes those examples
    parse at all."""
    out, i, n = [], 0, len(block)
    while i < n:
        if block[i] != '"':
            out.append(block[i])
            i += 1
            continue

        j, esc = i + 1, False
        while j < n:
            c = block[j]
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                break
            j += 1

        out.append('"' + join_wrapped(block[i + 1:j]) + '"')
        i = j + 1
    return "".join(out)


def extract(rfc, lines):
    """Yield (filename, bytes, note) for every example of the RFC."""
    for section, start, end, names in RFCS[rfc]["sections"]:
        kept = [l for l in lines[start - 1:end] if not FURNITURE.match(l)]
        found = blocks("\n".join(kept))

        if len(found) != len(names):
            raise SystemExit(
                "%s section %s: expected %d JSON block(s), found %d"
                % (rfc, section, len(names), len(found))
            )

        for block, name in zip(found, names):
            note = "verbatim"
            try:
                value = json.loads(block)
            except json.JSONDecodeError:
                value = json.loads(unwrap_strings(block))
                note = "wrapped strings rejoined"

            body = json.dumps(value, indent=2, ensure_ascii=False) + "\n"
            yield os.path.join(rfc, "%s_%s.json" % (section, name)), body.encode("utf-8"), note


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--rfc-dir", default=os.environ.get("RFC_DIR", os.path.expanduser("~/.local/share/rfc")))
    parser.add_argument("--out", default=DEFAULT_OUT)
    parser.add_argument("--check", action="store_true", help="report differences without writing")
    args = parser.parse_args()

    stale = []
    for rfc in sorted(RFCS):
        lines = source(rfc, args.rfc_dir)

        for name, body, note in extract(rfc, lines):
            path = os.path.join(args.out, name)
            current = open(path, "rb").read() if os.path.exists(path) else None

            if args.check:
                state = "up to date" if current == body else "STALE"
                if current != body:
                    stale.append(name)
            else:
                state = "unchanged" if current == body else "written"
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "wb") as f:
                    f.write(body)

            print("  %-52s %-24s %s" % (name, note, state))

    if stale:
        print("\n%d golden file(s) differ from the RFC; run without --check" % len(stale))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
