#!/usr/bin/env python3
"""Visualize maybenot trace logs averaged across many files as stacked bar charts."""

import argparse
import sys
from concurrent.futures import ProcessPoolExecutor
from functools import partial
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np


def parse_args():
    parser = argparse.ArgumentParser(
        description="Visualize averaged packet activity across many maybenot trace logs"
    )
    parser.add_argument("trace_dir", help="directory to search recursively for trace log files")
    parser.add_argument(
        "--bucket", type=float, default=0.1, metavar="FLOAT",
        help="bucket size in seconds (default: 0.1)"
    )
    parser.add_argument(
        "--window", type=float, default=20.0, metavar="FLOAT",
        help="time window in seconds (default: 20.0)"
    )
    parser.add_argument(
        "--output", metavar="PATH",
        help="save figure to file instead of displaying"
    )
    parser.add_argument(
        "--glob", default="*.log", metavar="PATTERN",
        help="file glob pattern (default: *.log)"
    )
    return parser.parse_args()


def process_file(path, num_buckets, bucket_size):
    sent_n = np.zeros(num_buckets)
    sent_d = np.zeros(num_buckets)
    recv_n = np.zeros(num_buckets)
    recv_d = np.zeros(num_buckets)

    with open(path) as f:
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
            bucket_idx = int(timestamp_s / bucket_size)
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

    return sent_n, sent_d, recv_n, recv_d


def main():
    args = parse_args()

    files = sorted(Path(args.trace_dir).rglob(args.glob))
    if not files:
        print(f"no files found matching '{args.glob}' in '{args.trace_dir}'", file=sys.stderr)
        sys.exit(1)

    n = len(files)
    num_buckets = int(args.window / args.bucket)

    total_sent_n = np.zeros(num_buckets)
    total_sent_d = np.zeros(num_buckets)
    total_recv_n = np.zeros(num_buckets)
    total_recv_d = np.zeros(num_buckets)

    worker = partial(process_file, num_buckets=num_buckets, bucket_size=args.bucket)
    with ProcessPoolExecutor() as executor:
        for sn, sd, rn, rd in executor.map(worker, files):
            total_sent_n += sn
            total_sent_d += sd
            total_recv_n += rn
            total_recv_d += rd

    sent_n = total_sent_n / n
    sent_d = total_sent_d / n
    recv_n = total_recv_n / n
    recv_d = total_recv_d / n

    x = np.arange(num_buckets) * args.bucket

    fig, ax = plt.subplots(figsize=(14, 5))

    ax.bar(x, sent_n, width=args.bucket, color="steelblue", label="Normal", align="edge")
    ax.bar(x, sent_d, width=args.bucket, color="darkorange", label="Decoy", bottom=sent_n, align="edge")
    ax.bar(x, -recv_n, width=args.bucket, color="steelblue", align="edge")
    ax.bar(x, -recv_d, width=args.bucket, color="darkorange", bottom=-recv_n, align="edge")

    ax.axhline(y=0, color="black", linewidth=0.5)
    ax.set_title(f"Sent (above) / Received (below) — averaged over {n} trace(s) - {args.trace_dir}")
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
