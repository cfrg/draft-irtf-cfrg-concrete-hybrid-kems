#!/bin/bash

# Script to regenerate JSON and markdown test vector files
cd reference-implementation
cargo run --bin generate_vectors -- >../test-vectors.json
cargo run --bin vectors_to_markdown -- ../test-vectors.json >../test-vectors.md
