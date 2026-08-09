#!/usr/bin/env python3
"""Write deployment-ready Authority V3 roster evidence."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from solslot_api.authority_v3_roster import export_authority_v3_roster


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--ceremony-id")
    args = parser.parse_args()
    output = Path(args.output).resolve()
    if output.exists():
        raise SystemExit("refusing to overwrite Authority V3 roster evidence")
    evidence = export_authority_v3_roster(
        args.database,
        ceremony_id=args.ceremony_id,
    )
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(evidence, handle, indent=2)
        handle.write("\n")
    print(
        json.dumps(
            {"output": str(output), "artifactHash": evidence["artifactHash"]}
        )
    )


if __name__ == "__main__":
    main()
