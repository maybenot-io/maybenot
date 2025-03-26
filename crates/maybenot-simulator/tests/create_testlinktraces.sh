#!/bin/bash

# Define sizebins and binpktsizes
sizebins_2="0,129,1501"
binpktsizes_2="128,1500"

sizebins_3="0, 201, 1401, 1501"
binpktsizes_3="100, 800, 1500"

sizebins_21="0, 49, 65, 81, 97, 113, 129, 145, 161, 193, 241, 289, 369, 449, 513, 577, 705, 849, 1009, 1201, 1421, 1501"
binpktsizes_21="48, 64, 80, 96, 112, 128, 144, 160, 192, 240, 288, 368, 448, 512, 576, 704, 848, 1008, 1200, 1420, 1500"


# Create std_res ether100M_10K trace and corresponding symmetric binary trace
../../../target/release/linktrace_util create-synthlinktrace \
    --save-file "ether100M_synth_10K_std.tr" \
    --linecount 10000\
    --preset "stdres_ether100M"

../../../target/release/linktrace_util create-tracebin-std \
    --ul-bw-tracefile "ether100M_synth_10K_std.tr" \
    --dl-bw-tracefile "ether100M_synth_10K_std.tr" \
    --save-file "ether100M_synth10K_std" \


# Create std_res ether10M_10K trace and an assymmetric binary trace
../../../target/release/linktrace_util create-synthlinktrace \
    --save-file "ether10M_synth_10K_std.tr" \
    --linecount 10000\
    --preset "stdres_ether10M"

../../../target/release/linktrace_util create-tracebin-std \
    --ul-bw-tracefile "ether10M_synth_10K_std.tr" \
    --dl-bw-tracefile "ether100M_synth_10K_std.tr" \
    --save-file "ether_100Mserv_10Mcli_10K_std" \


# Create std_res test100K_2M trace and corresponding symmetric binary trace
../../../target/release/linktrace_util create-synthlinktrace \
    --save-file "test100K_synth_2M_std.tr" \
    --linecount 2000000\
    --preset "stdres_test100K"

../../../target/release/linktrace_util create-tracebin-std \
    --ul-bw-tracefile "test100K_synth_2M_std.tr" \
    --dl-bw-tracefile "test100K_synth_2M_std.tr" \
    --save-file "test100K_synth2M_std" \


# Create ether100M_5K trace and corresponding symmetric binary trace
../../../target/release/linktrace_util create-synthlinktrace \
    --save-file "ether100M_synth5K.tr" \
    --linecount 5000\
    --preset "hires_ether100M"

../../../target/release/linktrace_util create-tracebin-hi \
    --ul-bw-tracefile "ether100M_synth5K.tr" \
    --dl-bw-tracefile "ether100M_synth5K.tr" \
    --save-file "ether100M_synth5K" \
    --sizebins "$sizebins_21" \
    --binpktsizes "$binpktsizes_21"


# Create ether100M_5M trace and corresponding symmetric binary trace
../../../target/release/linktrace_util create-synthlinktrace \
    --save-file "ether100M_synth5M.tr.gz" \
    --linecount 5000000\
    --preset "hires_ether100M"

../../../target/release/linktrace_util create-tracebin-hi \
    --ul-bw-tracefile "ether100M_synth5M.tr.gz" \
    --dl-bw-tracefile "ether100M_synth5M.tr.gz" \
    --save-file "ether100M_synth5M" \
    --sizebins "$sizebins_2" \
    --binpktsizes "$binpktsizes_2"

../../../target/release/linktrace_util create-tracebin-hi \
    --ul-bw-tracefile "ether100M_synth5M.tr.gz" \
    --dl-bw-tracefile "ether100M_synth5M.tr.gz" \
    --save-file "ether100M_synth5M_21bins" \
    --sizebins "$sizebins_21" \
    --binpktsizes "$binpktsizes_21"


# Create ether100M_10M trace and corresponding symmetric binary trace
../../../target/release/linktrace_util create-synthlinktrace \
    --save-file "ether100M_synth10M.tr.gz" \
    --linecount 10000000\
    --preset "hires_ether100M"

../../../target/release/linktrace_util create-tracebin-hi \
    --ul-bw-tracefile "ether100M_synth10M.tr.gz" \
    --dl-bw-tracefile "ether100M_synth10M.tr.gz" \
    --save-file "ether100M_synth10M" \
    --sizebins "$sizebins_2" \
    --binpktsizes "$binpktsizes_2"


# Create ether10M_5M trace and corresponding symmetric binary trace
../../../target/release/linktrace_util create-synthlinktrace \
    --save-file "ether10M_synth5M.tr.gz" \
    --linecount 5000000\
    --preset "hires_ether10M"

../../../target/release/linktrace_util create-tracebin-hi \
    --ul-bw-tracefile "ether10M_synth5M.tr.gz" \
    --dl-bw-tracefile "ether10M_synth5M.tr.gz" \
    --save-file "ether10M_synth5M" \
    --sizebins "$sizebins_2" \
    --binpktsizes "$binpktsizes_2"


# Create ether100M_40M trace and corresponding symmetric binary trace
../../../target/release/linktrace_util create-synthlinktrace \
    --save-file "ether100M_synth40M.tr.gz" \
    --linecount 40000000\
    --preset "hires_ether100M"

../../../target/release/linktrace_util create-tracebin-hi \
    --ul-bw-tracefile "ether100M_synth40M.tr.gz" \
    --dl-bw-tracefile "ether100M_synth40M.tr.gz" \
    --save-file "ether100M_synth40M" \
    --sizebins "$sizebins_2" \
    --binpktsizes "$binpktsizes_2"


# Create assymetric ether_100Mserv_10Mcli_5M binary trace
../../../target/release/linktrace_util create-tracebin-hi \
    --ul-bw-tracefile "ether10M_synth5M.tr.gz" \
    --dl-bw-tracefile "ether100M_synth5M.tr.gz" \
    --save-file "ether_100Mserv_10Mcli_5M" \
    --sizebins "$sizebins_2" \
    --binpktsizes "$binpktsizes_2"


echo "All traces and binary files created."

