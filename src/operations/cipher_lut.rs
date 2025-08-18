use tfhe::core_crypto::{
    fft_impl::fft64::{
        c64,
        crypto::wop_pbs::{
            blind_rotate_assign, cmux_tree_memory_optimized, vertical_packing,
            vertical_packing_scratch,
        },
    },
    prelude::*,
};
use tfhe::{
    boolean::prelude::PolynomialSize,
    core_crypto::prelude::{
        ComputationBuffers, Fft, FourierGgswCiphertextList, LweCiphertext, PolynomialList,
    },
};
/// 将多个查找表分别打包为密文查找表（每个查找表独立生成一个 PolynomialList）
///
/// # 参数
/// - `tables`: 多个查找表，每个元素是一个查找表（例如不同chunk分表或不同功能表）
/// - `polynomial_size`: 多项式阶数（每个GLWE多项式能装多少个元素）
/// - `delta`: 放大倍数（TFHE编码用）
///
/// # 返回
/// - `Vec<PolynomialList<Vec<u64>>>`: 每个查找表分别生成的密文查找表
///
/// # 用法
/// ```ignore
/// let lut_lists = generate_lut_from_vecs(&split_tables, PolynomialSize(1024), 1 << 40);
/// // lut_lists[i] 就是第 i 个查找表的密文查找表（PolynomialList）
/// ```
pub fn generate_lut_from_vecs(
    tables: &[Vec<usize>],
    polynomial_size: PolynomialSize,
    delta: u64,
) -> Vec<PolynomialList<Vec<u64>>> {
    let mut result = Vec::with_capacity(tables.len());

    for (table_idx, table) in tables.iter().enumerate() {
        let table_len = table.len();
        // 需要多少个多项式（每个多项式 polynomial_size.0 个元素，最后一个可能补0）
        let num_poly = (table_len + polynomial_size.0 - 1) / polynomial_size.0;

        // 先将所有多项式拼成一个一维向量（Concrete/TFHE标准格式）
        let mut flat: Vec<u64> = Vec::with_capacity(num_poly * polynomial_size.0);

        for poly_idx in 0..num_poly {
            for i in 0..polynomial_size.0 {
                let idx = poly_idx * polynomial_size.0 + i;
                let val = if idx < table_len {
                    (table[idx] as u64) * delta
                } else {
                    0
                };
                flat.push(val);
            }
        }

        // 构造 PolynomialList，flat 按多项式顺序拼接
        let poly_list = PolynomialList::from_container(flat, polynomial_size);
        result.push(poly_list);
    }
    result
}

pub fn generate_lut_from_vecs_auto(
    tables: &[Vec<usize>],
    polynomial_size: PolynomialSize,
    delta: u64,
) -> (Vec<PolynomialList<Vec<u64>>>, usize) {
    assert!(!tables.is_empty(), "tables must not be empty");

    let table_len = tables[0].len();
    for t in tables.iter().skip(1) {
        assert!(
            t.len() == table_len,
            "all tables must have the same length: expected {}, got {}",
            table_len,
            t.len()
        );
    }

    let n = polynomial_size.0;
    let per_poly_capacity = n / table_len;

    // =============== 情况 1：无法打包（一个表需要拆成多项式）===============
    if per_poly_capacity < 1 {
        let mut result = Vec::with_capacity(tables.len());

        for table in tables {
            let table_len = table.len();
            let num_poly = (table_len + n - 1) / n;

            let mut flat: Vec<u64> = Vec::with_capacity(num_poly * n);

            for poly_idx in 0..num_poly {
                for i in 0..n {
                    let idx = poly_idx * n + i;
                    let val = if idx < table_len {
                        (table[idx] as u64) * delta
                    } else {
                        0
                    };
                    flat.push(val);
                }
            }

            let poly_list = PolynomialList::from_container(flat, polynomial_size);
            result.push(poly_list);
        }

        return (result, 1);
    }

    // ==================== 情况 2：可打包（一个 poly 放多张表） ====================
    // 改动点：将每组打包（最多 per_poly_capacity 张表）生成一个独立的 PolynomialList，
    // 且该 PolynomialList 里只含 1 个 poly（长度 = n）
    let total_tables = tables.len();
    let num_groups = (total_tables + per_poly_capacity - 1) / per_poly_capacity;

    let mut result = Vec::with_capacity(num_groups);

    for g in 0..num_groups {
        // 为该组准备一个单-poly 的扁平存储（未占用处为 0）
        let mut flat = vec![0u64; n];

        // 本组中最多 per_poly_capacity 张表
        for s in 0..per_poly_capacity {
            let table_idx = g * per_poly_capacity + s;
            if table_idx >= total_tables {
                break;
            }

            // 将该表拷贝到本 poly 的对应分区 [s*table_len .. s*table_len + table_len)
            let slot_base = s * table_len;
            let table = &tables[table_idx];

            for j in 0..table_len {
                flat[slot_base + j] = (table[j] as u64) * delta;
            }
        }

        let poly_list = PolynomialList::from_container(flat, polynomial_size);
        // 注意：此时 poly_list 中只有 1 个多项式（因为 container 长度正好 = n）
        result.push(poly_list);
    }

    (result, per_poly_capacity)
}

/// 单查找表的TFHE vertical_packing查值函数
///
/// # 参数
/// - `lut`: 查找表（PolynomialList）
/// - `lwe_out`: 输出密文（LweCiphertext，mutable）
/// - `ggsw_list`: GGSW密钥组
/// - `fft`: FFT上下文
/// - `buffer`: 临时scratch buffer
/// - `lut_input_size`: 查找表输入bit数（或总输入数），需与GLWE参数对应
///
/// # 功能
/// 用vertical_packing做一次完整查找表查值。查找结果写入lwe_out。
pub fn tfhe_vertical_packing_lookup(
    lut: &PolynomialList<Vec<u64>>,
    lwe_out: &mut LweCiphertext<Vec<u64>>,
    ggsw_list: &FourierGgswCiphertextList<Vec<c64>>,
    fft: &Fft,
    buffer: &mut ComputationBuffers,
    lut_input_size: usize,
) {
    // 确保buffer大小足够
    buffer.resize(
        vertical_packing_scratch::<u64>(
            ggsw_list.glwe_size(),
            ggsw_list.polynomial_size(),
            lut.polynomial_count(),
            ggsw_list.count(),
            fft.as_view(),
        )
        .unwrap()
        .unaligned_bytes_required(),
    );
    let stack = buffer.stack();

    vertical_packing(
        lut.as_view(),
        lwe_out.as_mut_view(),
        ggsw_list.as_view(),
        fft.as_view(),
        stack,
    );
}

/// 多查找表批量vertical_packing查值
///
/// # 参数
/// - `luts`: 查找表数组（每个PolynomialList）
/// - `lwe_outs`: 输出密文数组（每个LweCiphertext）
/// - 其它同上
pub fn tfhe_vertical_packing_multi_lookup(
    luts: &[PolynomialList<Vec<u64>>],
    lwe_outs: &mut [LweCiphertext<Vec<u64>>],
    ggsw_list: &FourierGgswCiphertextList<Vec<c64>>,
    fft: &Fft,
    buffer: &mut ComputationBuffers,
    lut_input_size: usize,
) {
    assert_eq!(luts.len(), lwe_outs.len());
    for (lut, lwe_out) in luts.iter().zip(lwe_outs.iter_mut()) {
        tfhe_vertical_packing_lookup(lut, lwe_out, ggsw_list, fft, buffer, lut_input_size);
    }
}
