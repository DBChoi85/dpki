#!/usr/bin/env python3

import argparse
import csv
import os
import resource
import time


# ============================================================
# 기존 DPKI 코드 연결
# ============================================================

def commitment_generation(n):
    """
    TODO:
    기존 commitment generation 함수를 연결
    """
    raise NotImplementedError


def validator_reconstruction(n):
    """
    TODO:
    기존 validator C_V reconstruction 함수를 연결
    """
    raise NotImplementedError


WORKLOADS = {
    "commitment": commitment_generation,
    "validator": validator_reconstruction,
}


# ============================================================
# Measurement
# ============================================================

def get_cpu_time():
    usage = resource.getrusage(resource.RUSAGE_SELF)
    return usage.ru_utime + usage.ru_stime


def get_peak_rss_mb():
    # Linux: ru_maxrss is KiB
    usage = resource.getrusage(resource.RUSAGE_SELF)
    return usage.ru_maxrss / 1024.0


def measure(func, n, repeat):

    cpu_start = get_cpu_time()
    wall_start = time.perf_counter()

    for _ in range(repeat):
        func(n)

    wall_end = time.perf_counter()
    cpu_end = get_cpu_time()

    wall_time = wall_end - wall_start
    cpu_time = cpu_end - cpu_start

    cpu_percent = (
        cpu_time / wall_time * 100.0
        if wall_time > 0
        else 0.0
    )

    return {
        "wall_time_s": wall_time,
        "cpu_time_s": cpu_time,
        "cpu_percent": cpu_percent,
        "peak_rss_mb": get_peak_rss_mb(),
    }


# ============================================================
# CSV
# ============================================================

def append_csv(filename, row):

    exists = os.path.exists(filename)

    with open(filename, "a", newline="") as f:

        fieldnames = [
            "workload",
            "n",
            "run",
            "repeat",
            "wall_time_s",
            "cpu_time_s",
            "cpu_percent",
            "peak_rss_mb",
        ]

        writer = csv.DictWriter(
            f,
            fieldnames=fieldnames
        )

        if not exists:
            writer.writeheader()

        writer.writerow(row)


# ============================================================
# Main
# ============================================================

def main():

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--workload",
        choices=WORKLOADS.keys(),
        required=True,
    )

    parser.add_argument(
        "--n",
        type=int,
        required=True,
    )

    parser.add_argument(
        "--run",
        type=int,
        required=True,
    )

    parser.add_argument(
        "--repeat",
        type=int,
        default=1,
    )

    parser.add_argument(
        "--output",
        default="resource_usage_raw.csv",
    )

    args = parser.parse_args()

    func = WORKLOADS[args.workload]

    result = measure(
        func,
        args.n,
        args.repeat,
    )

    row = {
        "workload": args.workload,
        "n": args.n,
        "run": args.run,
        "repeat": args.repeat,
        **result,
    }

    append_csv(
        args.output,
        row,
    )

    print(
        f"{args.workload:12} "
        f"N={args.n:>6} "
        f"run={args.run:>2} "
        f"repeat={args.repeat:>6} "
        f"CPU={result['cpu_percent']:7.2f}% "
        f"PeakRSS={result['peak_rss_mb']:8.2f} MB "
        f"Wall={result['wall_time_s']:.4f}s"
    )


if __name__ == "__main__":
    main()
