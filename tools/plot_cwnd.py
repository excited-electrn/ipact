#!/usr/bin/env python3
"""Plot the CSV written by `IPACT_CWND_LOG=cwnd.csv ./build/blast ...`.   usage: plot_cwnd.py cwnd.csv [out.png]"""
import csv
import sys

import matplotlib
matplotlib.use("Agg")          # draw to a file, no window needed
import matplotlib.pyplot as plt

rows = list(csv.DictReader(open(sys.argv[1])))
t = [float(r["time_ms"]) for r in rows]
plt.figure(figsize=(9, 4))
plt.plot(t, [int(r["cwnd"]) for r in rows], label="cwnd")
plt.plot(t, [int(r["in_flight"]) for r in rows], label="bytes in flight", alpha=0.5)
ss = [int(r["ssthresh"]) or None for r in rows]            # 0 means "still infinite"
plt.plot(t, ss, "--", label="ssthresh")
plt.xlabel("time (ms)")
plt.ylabel("bytes")
plt.legend()
plt.tight_layout()
out = sys.argv[2] if len(sys.argv) > 2 else "cwnd.png"
plt.savefig(out, dpi=110)
print("wrote", out)
