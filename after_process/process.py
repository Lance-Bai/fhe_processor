import pandas as pd

# 读入数据
df = pd.read_csv("input.csv")

# 定义加权平均
def weighted_avg(group, col):
    return (group[col] * group['iters']).sum() / group['iters'].sum()

# 按 (n_bits, threads) 分组并计算
result = df.groupby(['n_bits', 'threads']).apply(
    lambda g: pd.Series({
        'avg_cbs_ms': weighted_avg(g, 'avg_cbs_ms'),
        'avg_lut_ms': weighted_avg(g, 'avg_lut_ms'),
        'avg_total_ms': weighted_avg(g, 'avg_total_ms'),
        'iters_total': g['iters'].sum()
    })
).reset_index()

# 输出
result.to_csv("result.csv", index=False)
