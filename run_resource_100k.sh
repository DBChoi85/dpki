#!/bin/bash

set -e

N=100000
RUNS=10

WORKLOAD="/home/dbc-gpu/dpki_experiment/dpki/workload_100000"

RESULT_DIR="resource_100k"
SUMMARY="${RESULT_DIR}/resource_summary.csv"

mkdir -p "$RESULT_DIR"

echo "run,cpu_percent,peak_rss_kb,peak_rss_mb,user_time_s,system_time_s,elapsed" \
    > "$SUMMARY"

for run in $(seq 1 $RUNS)
do
    echo "========================================"
    echo "N=${N}, Run ${run}/${RUNS}"
    echo "========================================"

    BENCHMARK_OUT="${RESULT_DIR}/benchmark_run_${run}.csv"
    TIME_LOG="${RESULT_DIR}/time_run_${run}.log"

    /usr/bin/time -v \
        python3 run_dpki_benchmark.py \
        --workload "$WORKLOAD" \
        --output "$BENCHMARK_OUT" \
        2> >(tee "$TIME_LOG" >&2)

    CPU=$(grep "Percent of CPU this job got" "$TIME_LOG" \
        | awk '{gsub("%","",$NF); print $NF}')

    RSS_KB=$(grep "Maximum resident set size" "$TIME_LOG" \
        | awk '{print $NF}')

    USER_TIME=$(grep "User time (seconds)" "$TIME_LOG" \
        | awk '{print $NF}')

    SYSTEM_TIME=$(grep "System time (seconds)" "$TIME_LOG" \
        | awk '{print $NF}')

    ELAPSED=$(grep "Elapsed (wall clock) time" "$TIME_LOG" \
        | awk '{print $NF}')

    RSS_MB=$(awk -v kb="$RSS_KB" \
        'BEGIN {printf "%.3f", kb / 1024}')

    echo "${run},${CPU},${RSS_KB},${RSS_MB},${USER_TIME},${SYSTEM_TIME},${ELAPSED}" \
        >> "$SUMMARY"

    echo
    echo "CPU       : ${CPU}%"
    echo "Peak RSS  : ${RSS_MB} MB"
    echo "User time : ${USER_TIME} s"
    echo "System    : ${SYSTEM_TIME} s"
    echo "Elapsed   : ${ELAPSED}"
    echo
done

echo "========================================"
echo "All 10 runs completed."
echo "========================================"
echo
cat "$SUMMARY"
