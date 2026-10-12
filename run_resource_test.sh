#!/bin/bash

set -e

OUT="resource_usage_raw.csv"

rm -f "$OUT"

for workload in commitment validator
do
    for n in 100 1000 10000 100000
    do
        case $n in
            100)
                repeat=10000
                ;;
            1000)
                repeat=1000
                ;;
            10000)
                repeat=100
                ;;
            100000)
                repeat=10
                ;;
        esac

        for run in $(seq 1 10)
        do
            python3 measure_resource.py \
                --workload "$workload" \
                --n "$n" \
                --run "$run" \
                --repeat "$repeat" \
                --output "$OUT"
        done
    done
done

echo
echo "Completed."
echo "Results: $OUT"
