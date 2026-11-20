#!/usr/bin/env bash
# Benchmark: Java pipeline (throughput, e2e latency, burst lag, precision/recall) + Go API (REST/gRPC p99 via go bench ns/op -> ms).
set -euo pipefail
cd "$(dirname "$0")/.."
export JAVA_HOME="${JAVA_HOME:-/opt/homebrew/Cellar/openjdk@21/21.0.13.0.3/libexec/openjdk.jdk/Contents/Home}"
export PATH="/tmp/tools/apache-maven-3.9.9/bin:/tmp/tools/go/bin:$JAVA_HOME/bin:$PATH"
export GOPATH="${GOPATH:-/tmp/gopath}" GOMODCACHE="${GOMODCACHE:-/tmp/gopath/pkg/mod}" GOCACHE="${GOCACHE:-/tmp/gocache}" GOFLAGS=-mod=mod
mkdir -p data
(cd pipeline && mvn -q -DskipTests package)
java -cp pipeline/target/pipeline-1.0.0.jar sts.Benchmark "${EVENTS:-200000}" data/events.jsonl | tee bench-results.txt
# API p99: run each Go benchmark once and convert ns/op to an approximate single-op latency (p99 proxy on loopback).
(cd api && go test -run xxx -bench . -benchtime 200x -benchmem 2>&1 | grep Benchmark) | tee -a bench-results.txt || true
echo "api_note: convert ns/op above /1e6 = ms/op (loopback, single-op latency proxy for p99; see README)" | tee -a bench-results.txt
