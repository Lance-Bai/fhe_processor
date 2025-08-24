# pip install concrete-python numpy
import numpy as np
from concrete import fhe

# ---- 1) 用 min/max 实现“无分支”的两两交换 ----
def swap_sorted(x, y):
    lo = np.minimum(x, y)   # FHE-friendly
    hi = np.maximum(x, y)   # FHE-friendly
    return lo, hi

# ---- 2) 5 元素冒泡排序：4 轮 pass，每轮做相邻 swap_sorted ----
@fhe.compiler({"arr": "encrypted"})
def bubble5(arr):
    # 为了让编译器更好做数据流分析，把元素拆出来做就地“交换”
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

    return np.array([a0, a1, a2, a3, a4], dtype=np.uint8)

# ---- 3) 编译：给出输入集合，Concrete 会自动推断位宽（这里是 8 bit）----
rng = np.random.default_rng(0)
inputset = [rng.integers(0, 256, size=5, dtype=np.uint8) for _ in range(60)]
circuit = bubble5.compile(inputset)  # 也可传 Configuration 调优

# ---- 4) 同态执行（加密→计算→解密 一步到位）----
sample = np.array([42, 17, 99, 8, 63], dtype=np.uint8)
sorted_plain = circuit.encrypt_run_decrypt(sample)
print("sorted =", sorted_plain.tolist())
