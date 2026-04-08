#!/usr/bin/env bash
set -e

bench_for_table_gen_kb() {
    local table_gen_kb=$1
    echo "===== Benchmark results for ECMULT_GEN_KB=$table_gen_kb ====="
    rm -rf build
    cmake -B build -DCMAKE_BUILD_TYPE=Release -DSECP256K1_ECMULT_GEN_KB=$table_gen_kb > build.log 2>&1
    cmake --build build -j6 >> build.log 2>&1
    ./build/bin/bench_ecmult | head -n4 | tail -n2
    ./build/bin/bench tweak | tail -n1
    echo ""
}

bench_for_table_gen_kb 2
bench_for_table_gen_kb 22
bench_for_table_gen_kb 86
bench_for_table_gen_kb 148
bench_for_table_gen_kb 256
bench_for_table_gen_kb 464
bench_for_table_gen_kb 832
bench_for_table_gen_kb 1536
bench_for_table_gen_kb 2816
bench_for_table_gen_kb 5120
bench_for_table_gen_kb 9728
bench_for_table_gen_kb 18432
