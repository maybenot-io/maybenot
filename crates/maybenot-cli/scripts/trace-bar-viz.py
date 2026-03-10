#!/usr/bin/env python3
"""Visualize maybenot trace logs as stacked bar charts of packet activity over time."""

import argparse
import sys

import matplotlib.pyplot as plt
import numpy as np


def parse_args():
    parser = argparse.ArgumentParser(
        description="Visualize maybenot trace log packet activity over time"
    )
    parser.add_argument("trace_log", help="input trace log file path")
    parser.add_argument(
        "--bucket", type=float, default=0.1, metavar="FLOAT",
        help="bucket size in seconds (default: 0.1)"
    )
    parser.add_argument(
        "--window", type=float, default=20.0, metavar="FLOAT",
        help="time window in seconds (default: 20)"
    )
    parser.add_argument(
        "--output", metavar="PATH",
        help="save figure to file instead of displaying"
    )
    return parser.parse_args()


def main():
    args = parse_args()

    num_buckets = int(args.window / args.bucket)
    sent_n = np.zeros(num_buckets)
    sent_d = np.zeros(num_buckets)
    recv_n = np.zeros(num_buckets)
    recv_d = np.zeros(num_buckets)

    with open(args.trace_log) as f:
        for line in f:
            parts = line.strip().split(",")
            if len(parts) < 2:
                continue
            try:
                timestamp_ns = int(parts[0])
            except ValueError:
                continue
            dir_type = parts[1]
            if len(dir_type) < 2:
                continue

            timestamp_s = timestamp_ns / 1e9
            bucket_idx = int(timestamp_s / args.bucket)
            if bucket_idx >= num_buckets:
                continue

            direction = dir_type[0]
            pkt_type = dir_type[1]

            if direction == "s" and pkt_type == "n":
                sent_n[bucket_idx] += 1
            elif direction == "s" and pkt_type == "d":
                sent_d[bucket_idx] += 1
            elif direction == "r" and pkt_type == "n":
                recv_n[bucket_idx] += 1
            elif direction == "r" and pkt_type == "d":
                recv_d[bucket_idx] += 1

    x = np.arange(num_buckets) * args.bucket

    fig, ax = plt.subplots(figsize=(14, 5))

    ax.bar(x, sent_n, width=args.bucket, color="steelblue", label="Normal", align="edge")
    ax.bar(x, sent_d, width=args.bucket, color="darkorange", label="Decoy", bottom=sent_n, align="edge")
    ax.bar(x, -recv_n, width=args.bucket, color="steelblue", align="edge")
    ax.bar(x, -recv_d, width=args.bucket, color="darkorange", bottom=-recv_n, align="edge")

    ax.axhline(y=0, color="black", linewidth=0.5)
    ax.set_title("Sent (above) / Received (below)")
    ax.set_xlabel("time since first packet (s)")
    ax.set_ylabel(f"packets per {args.bucket}s bucket")
    ax.legend()
    plt.tight_layout()

    if args.output:
        plt.savefig(args.output)
        print(f"saved to {args.output}")
    else:
        plt.show()


if __name__ == "__main__":
    main()
