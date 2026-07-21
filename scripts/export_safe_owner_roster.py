#!/usr/bin/env python3
"""Write a public 2-of-3 Safe roster from the latest enrolled ceremony."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from solslot_api.safe_owner_roster import export_safe_owner_roster


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--ceremony-id")
    args = parser.parse_args()
    output = Path(args.output).resolve()
    if output.exists():
        raise SystemExit("refusing to overwrite Safe owner roster evidence")
    evidence = export_safe_owner_roster(
        args.database,
        ceremony_id=args.ceremony_id,
    )
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(evidence, handle, indent=2)
        handle.write("\n")
    print(json.dumps({"output": str(output), "artifactHash": evidence["artifactHash"]}))


if __name__ == "__main__":
    main()
