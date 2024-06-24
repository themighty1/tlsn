#! /bin/bash

# Check if we are running as root
# if [ "$EUID" -ne 0 ]; then
#   echo "This script must be run as root"
#   exit
# fi

# Run the benchmark binary
#VERIFIER_IP=127.0.0.1 VERIFIER_PORT=12344 ../../target/x86_64-unknown-linux-gnu/release/bench
../../target/x86_64-unknown-linux-gnu/release/bench

# Plot the results
../../target/x86_64-unknown-linux-gnu/release/plot metrics.csv
