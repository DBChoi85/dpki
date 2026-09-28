#!/usr/bin/env bash
set -euo pipefail
python prepare_workload.py --n 100000 --revoke-ratio 0.10 --seed 20260903 --output workload_100k_10pct

echo "Run CRL in this fresh process:"
echo "python run_crl_benchmark.py --workload workload_100k_10pct --repeats 5 --output results_crl_100k_10pct"

echo "Then, in a separate fresh process:"
echo "python run_dpki_benchmark.py --workload workload_100k_10pct --queries 5000 --warmup 500 --domain D01-A --output results_dpki_100k_10pct"
