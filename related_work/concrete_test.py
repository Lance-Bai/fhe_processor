# concrete_test.py
# pip install concrete-python numpy

import os
import time
import contextlib
import numpy as np
from concrete import fhe


# ───────────────────── 预设：给 Rayon 一个明确的并行规模（可选但推荐） ─────────────────────
# 放在任何 FHE 计算之前；这样先进行的多线程调用会按该规模初始化线程池
os.environ.setdefault("RAYON_NUM_THREADS", str(os.cpu_count() or 4))


# ────────────────────────────── 工具：线程/亲和性控制 ──────────────────────────────

@contextlib.contextmanager
def single_thread_env():
    """临时把常见并行库线程数限制为 1。块结束后自动恢复。"""
    keys = [
        "RAYON_NUM_THREADS",        # Rust rayon（Concrete/Rust侧经常用）
        "OMP_NUM_THREADS",          # OpenMP
        "OPENBLAS_NUM_THREADS",     # OpenBLAS
        "MKL_NUM_THREADS",          # MKL
        "NUMEXPR_NUM_THREADS",      # numexpr
        "BLIS_NUM_THREADS",         # BLIS
        "VECLIB_MAXIMUM_THREADS",   # Accelerate/vecLib（macOS；Linux下通常无效）
    ]
    backup = {k: os.environ.get(k) for k in keys}
    try:
        for k in keys:
            os.environ[k] = "1"
        yield
    finally:
        for k, v in backup.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


@contextlib.contextmanager
def single_core_affinity(cpu_id: int = 0):
    """把当前进程临时绑到单个 CPU 核（Linux）。块结束后自动恢复。"""
    try:
        old = os.sched_getaffinity(0)   # 备份
        os.sched_setaffinity(0, {cpu_id})
        yield
    finally:
        try:
            os.sched_setaffinity(0, old)
        except Exception:
            pass


def time_single_core(callable_fn, *args, **kwargs):
    """在单核+单线程环境下执行 callable_fn(*args, **kwargs)，返回(结果, 耗时秒)。"""
    with single_thread_env(), single_core_affinity(cpu_id=0):
        t0 = time.perf_counter()
        out = callable_fn(*args, **kwargs)
        t1 = time.perf_counter()
    return out, (t1 - t0)


def time_multi_core(callable_fn, *args, **kwargs):
    """多线程/多核（默认环境）下执行 callable_fn(*args, **kwargs)，返回(结果, 耗时秒)。"""
    t0 = time.perf_counter()
    out = callable_fn(*args, **kwargs)
    t1 = time.perf_counter()
    return out, (t1 - t0)


# ────────────────────────────── FHE 逻辑：排序/聚合 ──────────────────────────────

# 无分支的两两交换（最小值在前，最大值在后）
def swap_sorted(x, y):
    lo = np.minimum(x, y)
    hi = np.maximum(x, y)
    return lo, hi


# 5 元素冒泡排序，多输出（tuple）
@fhe.compiler({"arr": "encrypted"})
def bubble5_multi(arr):
    a0, a1, a2, a3, a4 = arr[0], arr[1], arr[2], arr[3], arr[4]

    # pass 1
    a0, a1 = swap_sorted(a0, a1)
    a1, a2 = swap_sorted(a1, a2)
    a2, a3 = swap_sorted(a2, a3)
    a3, a4 = swap_sorted(a3, a4)

    # pass 2
    a0, a1 = swap_sorted(a0, a1)
    a1, a2 = swap_sorted(a1, a2)
    a2, a3 = swap_sorted(a2, a3)

    # pass 3
    a0, a1 = swap_sorted(a0, a1)
    a1, a2 = swap_sorted(a1, a2)

    # pass 4
    a0, a1 = swap_sorted(a0, a1)

    # 直接返回 tuple（Concrete 支持多输出）
    return a0, a1, a2, a3, a4


# 最大值（单标量输出）
@fhe.compiler({"arr": "encrypted"})
def max5(arr):
    a0, a1, a2, a3, a4 = arr
    m01 = np.maximum(a0, a1)
    m23 = np.maximum(a2, a3)
    m0123 = np.maximum(m01, m23)
    return np.maximum(m0123, a4)


# 平均值（整数除法，单标量输出）
@fhe.compiler({"arr": "encrypted"})
def mean5(arr):
    a0, a1, a2, a3, a4 = arr
    s = a0 + a1 + a2 + a3 + a4
    return s // 5


# 平方和（单标量输出）
@fhe.compiler({"arr": "encrypted"})
def sumsq5(arr):
    a0, a1, a2, a3, a4 = arr
    return a0 * a0 + a1 * a1 + a2 * a2 + a3 * a3 + a4 * a4


# ────────────────────────────── 输入集合生成 ──────────────────────────────

def sweep_each_axis(base: int = 128, axis_step: int = 1):
    """
    轴向覆盖：对每个位置 pos，令其它位置为 base，仅让 pos 取 0..255（步长 axis_step）。
    axis_step=1 时为严格全覆盖（每个位置 256 条）。
    返回总数：5 * ceil(256/axis_step)
    """
    xs = []
    for pos in range(5):
        for v in range(0, 256, axis_step):
            vec = np.full(5, base, dtype=np.uint8)
            vec[pos] = np.uint8(v)
            xs.append(vec)
    return xs


def extremes_and_mixes():
    """极端与组合极端，帮助触达和/平方和上界。"""
    return [
        np.zeros(5, dtype=np.uint8),
        np.full(5, 255, dtype=np.uint8),
        np.array([255, 0, 0, 0, 0], dtype=np.uint8),
        np.array([0, 255, 0, 0, 0], dtype=np.uint8),
        np.array([255, 255, 255, 255, 0], dtype=np.uint8),
        np.full(5, 100, dtype=np.uint8),
        np.full(5, 200, dtype=np.uint8),
    ]

def cover_adjacent_pairs(base: int = 128, pair_step: int | None = 16):
    """
    相邻对覆盖：对 (0,1),(1,2),(2,3),(3,4)，两坐标做 0..255 的笛卡尔积（步长 pair_step），其它为 base。
    pair_step=None 表示不添加此项。
    返回总数：4 * (256/pair_step)^2
    """
    if pair_step is None:
        return []
    xs = []
    for i in range(4):
        for v in range(0, 256, pair_step):
            for w in range(0, 256, pair_step):
                vec = np.full(5, base, dtype=np.uint8)
                vec[i], vec[i + 1] = np.uint8(v), np.uint8(w)
                xs.append(vec)
    return xs


def make_inputset_strong(rng, profile: str = "standard"):
    """
    生成稳健的输入集合（按 profile 调覆盖强度）：
      - quick   : 轴向步长 8，相邻对步长 16，随机 64
      - standard: 轴向全覆盖，相邻对步长 16，随机 128
      - strict  : 轴向全覆盖，相邻对步长 8， 随机 256
    """
    profile = profile.lower()
    if profile == "quick":
        axis_step, pair_step, extra_random = 8, 16, 64
    elif profile == "strict":
        axis_step, pair_step, extra_random = 1, 8, 256
    else:
        # standard
        axis_step, pair_step, extra_random = 1, 16, 128

    xs = []
    xs += sweep_each_axis(base=128, axis_step=axis_step)
    xs += extremes_and_mixes()
    xs += cover_adjacent_pairs(base=128, pair_step=pair_step)
    if extra_random > 0:
        xs.extend(rng.integers(0, 256, size=(extra_random, 5), dtype=np.uint8))

    return xs
# ────────────────────────────── 主流程 ──────────────────────────────

def main():
    rng = np.random.default_rng(0)

    inputset = make_inputset_strong(rng, profile="strict")

    print("Compiling circuits...")
    circuit_sort  = bubble5_multi.compile(inputset)
    circuit_max   = max5.compile(inputset)
    circuit_mean  = mean5.compile(inputset)
    circuit_sumsq = sumsq5.compile(inputset)

    sample = np.array([42, 17, 99, 8, 63], dtype=np.uint8)
    print("Sample  :", sample.tolist())
    print("Start tests...")
    out_max,   t_max   = time_single_core(circuit_max.encrypt_run_decrypt, sample)
    out_mean,  t_mean  = time_single_core(circuit_mean.encrypt_run_decrypt, sample)
    out_sumsq, t_sumsq = time_single_core(circuit_sumsq.encrypt_run_decrypt, sample)
    out_sort, t_sort = time_single_core(circuit_sort.encrypt_run_decrypt, sample)
    print(f"Max     : {int(out_max)}   (multi-core {t_max*1e3:.2f} ms)")
    print(f"Mean    : {int(out_mean)}  (multi-core {t_mean*1e3:.2f} ms)")
    print(f"SumSq   : {int(out_sumsq)} (multi-core {t_sumsq*1e3:.2f} ms)")
    print("Sorted  :", list(out_sort))
    print(f"encrypt_run_decrypt (sort, single-core): {t_sort*1e3:.2f} ms")
    

    ok = True
    for _ in range(3):
        s = rng.integers(0, 256, size=5, dtype=np.uint8)
        so = list(circuit_sort.encrypt_run_decrypt(s))
        if so != sorted(s.tolist()):
            ok = False
            print("Sort mismatch:", s.tolist(), "->", so)
        if int(circuit_max.encrypt_run_decrypt(s)) != max(s):
            ok = False
            print("Max mismatch :", s.tolist())
        if int(circuit_mean.encrypt_run_decrypt(s)) != (sum(int(x) for x in s) // 5):
            ok = False
            print("Mean mismatch:", s.tolist())
        if int(circuit_sumsq.encrypt_run_decrypt(s)) != sum(int(x)*int(x) for x in s):
            ok = False
            print("SumSq mismatch:", s.tolist())
    print("Quick check:", "OK" if ok else "FAILED")
    
if __name__ == "__main__":
    main()
