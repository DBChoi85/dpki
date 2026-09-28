#!/usr/bin/env python3
from __future__ import annotations
import argparse, csv, json, math, statistics, subprocess, sys, time
from pathlib import Path

# Two-sided 95% Student-t critical values for df=1..30.
_T95 = {
    1:12.706,2:4.303,3:3.182,4:2.776,5:2.571,6:2.447,7:2.365,8:2.306,9:2.262,
    10:2.228,11:2.201,12:2.179,13:2.160,14:2.145,15:2.131,16:2.120,17:2.110,
    18:2.101,19:2.093,20:2.086,21:2.080,22:2.074,23:2.069,24:2.064,25:2.060,
    26:2.056,27:2.052,28:2.048,29:2.045,30:2.042,
}

def t95(df: int) -> float:
    return _T95.get(df, 1.96)

def read_metric_csv(path: Path) -> dict[str, float]:
    out = {}
    with path.open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            try:
                out[row["metric"]] = float(row["value"])
            except (ValueError, TypeError):
                pass
    return out

def read_summary(path: Path) -> dict[str, dict[str, float | str]]:
    out = {}
    with path.open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            out[row["metric"]] = row
    return out

def stats(xs: list[float]) -> dict[str, float | int]:
    n = len(xs)
    mean = statistics.fmean(xs)
    sd = statistics.stdev(xs) if n > 1 else 0.0
    half = t95(n - 1) * sd / math.sqrt(n) if n > 1 else 0.0
    return {
        "n_runs": n,
        "mean": mean,
        "sd": sd,
        "ci95_low": mean - half,
        "ci95_high": mean + half,
        "min": min(xs),
        "max": max(xs),
    }

def main():
    ap = argparse.ArgumentParser(description="Repeat independent Besu DPKI E2E runs and aggregate statistics.")
    ap.add_argument("--workload", required=True)
    ap.add_argument("--repeats", type=int, default=10)
    ap.add_argument("--queries", type=int, default=5000)
    ap.add_argument("--warmup", type=int, default=500)
    ap.add_argument("--domain-prefix", default="D01-A-besu")
    ap.add_argument("--output", default="results/besu_repeated")
    ap.add_argument("--rpc", default=None)
    ap.add_argument("--artifact", default="build/DPKICommitmentRegistry.json")
    args = ap.parse_args()

    if args.repeats < 2:
        raise SystemExit("--repeats must be at least 2 for variability statistics")

    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    all_init: list[dict[str, float]] = []
    all_verify: list[dict[str, dict[str, float | str]]] = []

    print(f"Besu repeated E2E benchmark: {args.repeats} independent runs", flush=True)
    print(f"Workload: {args.workload}", flush=True)
    print(f"Queries/run: {args.queries:,}; warmup/run: {args.warmup:,}", flush=True)

    total0 = time.perf_counter()
    for i in range(1, args.repeats + 1):
        domain = f"{args.domain_prefix}-run-{i:02d}"
        run_dir = out / f"run_{i:02d}"
        cmd = [
            sys.executable, "run_dpki_benchmark.py",
            "--workload", args.workload,
            "--queries", str(args.queries),
            "--warmup", str(args.warmup),
            "--domain", domain,
            "--output", str(run_dir),
            "--artifact", args.artifact,
        ]
        if args.rpc:
            cmd += ["--rpc", args.rpc]

        print(f"\n[{i}/{args.repeats}] domain={domain}", flush=True)
        run0 = time.perf_counter()
        result = subprocess.run(cmd)
        if result.returncode != 0:
            raise SystemExit(f"Run {i} failed with exit code {result.returncode}")

        init = read_metric_csv(run_dir / "initialization_metrics.csv")
        verify = read_summary(run_dir / "summary_verification_queries.csv")
        all_init.append(init)
        all_verify.append(verify)
        print(
            f"[{i}/{args.repeats}] done in {time.perf_counter()-run0:.2f}s | "
            f"proposal={init.get('besu_proposal_confirmation_ms', float('nan')):.2f} ms | "
            f"validator={init.get('validator_commitment_reconstruction_ms', float('nan')):.3f} ms | "
            f"finalize={init.get('besu_validation_confirmation_ms', float('nan')):.2f} ms | "
            f"root_match={int(init.get('pre_anchor_root_match', 0))}",
            flush=True,
        )

    init_metrics = [
        "besu_proposal_confirmation_ms",
        "validator_commitment_reconstruction_ms",
        "besu_validation_confirmation_ms",
        "besu_proposal_gas_used",
        "besu_validation_gas_used",
        "initialization_e2e_ms",
    ]
    init_rows = []
    for metric in init_metrics:
        xs = [r[metric] for r in all_init if metric in r]
        if xs:
            init_rows.append({"metric": metric, **stats(xs)})

    with (out / "summary_besu_runs.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=init_rows[0].keys())
        w.writeheader()
        w.writerows(init_rows)

    # Aggregate the per-run means of post-anchoring verification metrics.
    verify_rows = []
    metric_names = sorted(set().union(*(v.keys() for v in all_verify)))
    for metric in metric_names:
        xs = []
        unit = ""
        for v in all_verify:
            if metric in v:
                xs.append(float(v[metric]["mean"]))
                unit = str(v[metric]["unit"])
        if xs:
            verify_rows.append({"metric": metric, "unit": unit, **stats(xs)})

    with (out / "summary_verification_across_runs.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=verify_rows[0].keys())
        w.writeheader()
        w.writerows(verify_rows)

    raw_rows = []
    for i, init in enumerate(all_init, 1):
        raw_rows.append({"run": i, **{m: init.get(m, "") for m in init_metrics},
                         "pre_anchor_root_match": init.get("pre_anchor_root_match", "")})
    with (out / "raw_besu_runs.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=raw_rows[0].keys())
        w.writeheader()
        w.writerows(raw_rows)

    env = {
        "workload": args.workload,
        "repeats": args.repeats,
        "queries_per_run": args.queries,
        "warmup_per_run": args.warmup,
        "domain_prefix": args.domain_prefix,
        "artifact": args.artifact,
        "rpc_source": "--rpc" if args.rpc else "BESU_RPC_URL environment variable",
        "ci_method": "two-sided 95% Student-t interval over independent run-level measurements",
    }
    (out / "environment_besu_repeated.json").write_text(json.dumps(env, indent=2), encoding="utf-8")

    if any(int(r.get("pre_anchor_root_match", 0)) != 1 for r in all_init):
        raise SystemExit("FAIL: at least one run did not satisfy C_D == C_V")

    print(f"\nAll {args.repeats} runs completed successfully in {time.perf_counter()-total0:.1f}s.", flush=True)
    print(f"Summary: {out/'summary_besu_runs.csv'}", flush=True)
    print(f"Verification: {out/'summary_verification_across_runs.csv'}", flush=True)

if __name__ == "__main__":
    main()
