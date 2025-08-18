#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# usage:
#   python plot_by_threads.py input.csv [out_dir]
#
# - 从 input.csv 读取数据
# - 按 threads 分组，每个线程一张图
# - 横轴：n_bits（整数刻度）；纵轴：时间（ms）
# - 三条曲线：avg_cbs_ms / avg_lut_ms / avg_total_ms
# - 图片保存到 out_dir（默认当前目录）

import sys
import os
import pandas as pd
import matplotlib.pyplot as plt

def main(inp: str, out_dir: str = "."):
    os.makedirs(out_dir, exist_ok=True)

    df = pd.read_csv(inp)
    # 确保排序 & n_bits 是整数用于 x 轴刻度
    if not pd.api.types.is_integer_dtype(df["n_bits"]):
        df["n_bits"] = df["n_bits"].astype(int)

    threads_values = sorted(df["threads"].unique())
    for thread in threads_values:
        subdf = df[df["threads"] == thread].sort_values("n_bits")

        plt.figure(figsize=(8, 5))
        plt.plot(subdf["n_bits"], subdf["avg_cbs_ms"], marker="o", label="avg_cbs_ms")
        plt.plot(subdf["n_bits"], subdf["avg_lut_ms"], marker="s", label="avg_lut_ms")
        plt.plot(subdf["n_bits"], subdf["avg_total_ms"], marker="^", label="avg_total_ms")

        plt.title(f"Threads = {thread}")
        plt.xlabel("n_bits")
        plt.ylabel("Time (ms)")
        plt.legend()
        plt.grid(True)

        # x 轴使用 n_bits 的整数刻度
        xticks = subdf["n_bits"].unique()
        plt.xticks(xticks)

        plt.tight_layout()
        out_path = os.path.join(out_dir, f"perf_threads_{int(thread)}_intx.png")
        plt.savefig(out_path, dpi=150)
        plt.close()
        print(f"saved: {out_path}")

if __name__ == "__main__":
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print("Usage: python plot_by_threads.py <input.csv> [out_dir]")
        sys.exit(1)
    inp = sys.argv[1]
    out_dir = sys.argv[2] if len(sys.argv) == 3 else "."
    main(inp, out_dir)
