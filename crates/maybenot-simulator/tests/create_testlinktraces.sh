#!/bin/bash

# Define sizebins and binpktsizes
sizebins_2="0,129,1501"
binpktsizes_2="128,1500"

sizebins_21="0, 49, 65, 81, 97, 113, 129, 145, 161, 193, 241, 289, 369, 449, 513, 577, 705, 849, 1009, 1201, 1421, 1501"
binpktsizes_21="48, 64, 80, 96, 112, 128, 144, 160, 192, 240, 288, 368, 448, 512, 576, 704, 848, 1008, 1200, 1420, 1500"

  

# Create ether5K trace and corresponding binary
../../../target/release/linktrace_util create-synthlinktrace --filename "ether100M_synth5K.tr" --preset "ether100M_5K"
../../../target/release/linktrace_util create-tracebin --tracefile "ether100M_synth5K.tr" --sizebins "$sizebins_21" --binpktsizes "$binpktsizes_21"

# Create ether5M trace and corresponding binary
../../../target/release/linktrace_util create-synthlinktrace --filename "ether100M_synth5M.tr.gz" --preset "ether100M_5M"
../../../target/release/linktrace_util create-tracebin --tracefile "ether100M_synth5M.tr.gz" --sizebins "$sizebins_2" --binpktsizes "$binpktsizes_2"

# Create ether40M trace and corresponding binary
../../../target/release/linktrace_util create-synthlinktrace --filename "ether100M_synth40M.tr.gz" --preset "ether100M_40M"
../../../target/release/linktrace_util create-tracebin --tracefile "ether100M_synth40M.tr.gz" --sizebins "$sizebins_2" --binpktsizes "$binpktsizes_2"

echo "All traces and binary files created."

