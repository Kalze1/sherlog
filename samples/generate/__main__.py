"""Generate the sample evidence sets: ``python -m samples.generate [--out DIR] [names...]``."""

from __future__ import annotations

import argparse
from pathlib import Path

from samples.generate import SCENARIOS


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate SherLog sample evidence sets.")
    parser.add_argument(
        "names", nargs="*", help=f"Scenarios (default: all): {', '.join(SCENARIOS)}"
    )
    parser.add_argument("--out", type=Path, default=Path("samples/out"), help="Output directory.")
    args = parser.parse_args()
    unknown = set(args.names) - set(SCENARIOS)
    if unknown:
        parser.error(f"unknown scenario(s): {', '.join(sorted(unknown))}")
    for name in args.names or SCENARIOS:
        path = SCENARIOS[name](args.out)
        print(f"{name}: {path}  (evidence/ + answer_key.json)")


if __name__ == "__main__":
    main()
