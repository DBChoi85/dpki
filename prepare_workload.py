#!/usr/bin/env python3
import argparse, csv, json, random
from pathlib import Path

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, required=True)
    ap.add_argument("--revoke-ratio", type=float, default=0.10)
    ap.add_argument("--seed", type=int, default=20260903)
    ap.add_argument("--output", default="workload")
    args = ap.parse_args()

    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)

    revoked_count = round(args.n * args.revoke_ratio)
    rng = random.Random(args.seed)

    # Deterministic unique revoked serials from the same global population.
    revoked = sorted(rng.sample(range(1, args.n + 1), revoked_count))

    with (out/"revoked_serials.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["serial"])
        w.writerows([[x] for x in revoked])

    meta = {
        "n": args.n,
        "revoke_ratio": args.revoke_ratio,
        "revoked_count": revoked_count,
        "seed": args.seed,
        "serial_range": [1, args.n]
    }
    (out/"workload.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")

    print(json.dumps(meta, indent=2))
    print("revoked_serials:", out/"revoked_serials.csv")

if __name__ == "__main__":
    main()
