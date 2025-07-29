use crate::operations::{mask_chunk::masking_chunk_msb, operand::ArithmeticOp};

/// 生成一个查找表，每个表项是完整plain_log位宽的运算结果
pub fn get_plain_lut(plain_log: usize, op: &ArithmeticOp) -> Vec<usize> {
    let lut_input_size: usize = 1 << (plain_log * 2);
    let mut lut = Vec::with_capacity(lut_input_size);

    for i in 0..lut_input_size {
        let result = op.compute_split(i, plain_log);
        lut.push(result);
    }
    lut
}

/// 将一个大整数input，按位宽数组拆为Vec，每个元素就是对应输入端的明文
fn split_inputs(input: usize, bitwidths: &[usize]) -> Vec<usize> {
    let mut outs = Vec::with_capacity(bitwidths.len());
    let mut tmp = input;
    for &w in bitwidths {
        outs.push(tmp & ((1 << w) - 1));
        tmp >>= w;
    }
    outs
}

/// 对应输入每一块分别做掩码变换后拼接，得到掩码空间的查找表
pub fn adjust_lut_with_masking(
    plain_lut: &[usize],
    input_bitwidths: &[usize],
    chunk_size: usize,
) -> Vec<usize> {
    let total_bits: usize = input_bitwidths.iter().sum();
    let lut_input_size = 1 << total_bits;
    (0..lut_input_size)
        .map(|i| {
            let mut idxs = Vec::with_capacity(input_bitwidths.len());
            let mut acc = i;
            for &bits in input_bitwidths {
                idxs.push(acc & ((1 << bits) - 1));
                acc >>= bits;
            }
            let mut masked_input = 0usize;
            let mut offset = 0;
            for (block, &bits) in idxs.iter().zip(input_bitwidths) {
                let masked_block = masking_chunk_msb(*block, chunk_size, bits);
                masked_input |= masked_block << offset;
                offset += bits;
            }
            plain_lut[masked_input]
        })
        .collect()
}

pub fn split_adjusted_lut_by_chunk(
    //低位在前
    adjusted_lut: &[usize], // 长度 = 1 << 总输入bit数
    plain_log: usize,       // 结果位宽
    chunk_size: usize,
) -> Vec<Vec<usize>> {
    assert!(
        plain_log % chunk_size == 0,
        "plain_log 必须被 chunk_size 整除"
    );
    let segments = plain_log / chunk_size;
    let mask = (1 << chunk_size) - 1;
    let len = adjusted_lut.len();

    let mut result_tables = vec![Vec::with_capacity(len); segments];

    for value in adjusted_lut {
        for seg in 0..segments {
            let chunk = (value >> (seg * chunk_size)) & mask;
            result_tables[seg].push(chunk);
        }
    }
    result_tables
}

/// # 参数
/// - `plain_log`: 每个输入的明文位宽（如8）
/// - `input_bitwidths`: 各输入的bit宽数组（如vec![8, 8]）
/// - `chunk_size`: 分chunk位宽（如4）
/// - `op`: 算术操作符
///
/// # 返回
/// - `Vec<Vec<usize>>`：分chunk的查找表（每个Vec是一个chunk的表）
///
/// # 用法
/// ```ignore
/// let chunk_tables = build_split_lut_tables(8, vec![8,8], 4, &ArithmeticOp::Add);
/// ```
pub fn build_split_lut_tables(
    plain_log: usize,
    input_bitwidths: Vec<usize>,
    chunk_size: usize,
    op: &ArithmeticOp,
) -> Vec<Vec<usize>> {
    // 1. 生成明文查找表
    let plain_lut = get_plain_lut(plain_log, op);

    // 2. 掩码调整
    let adjusted_lut = adjust_lut_with_masking(&plain_lut, &input_bitwidths, chunk_size);

    // 3. 拆分为chunk分表
    split_adjusted_lut_by_chunk(&adjusted_lut, plain_log, chunk_size)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_lut_masking_chunk_correctness() {
        use crate::operations::{mask_chunk::masking_chunk_msb, operand::ArithmeticOp};

        let plain_log = 8;
        let chunk_size = 4;
        let input_bitwidths = vec![plain_log; 2];
        let op = ArithmeticOp::Add;

        let lut_input_size = 1 << (plain_log * 2);
        let plain_lut: Vec<usize> = (0..lut_input_size)
            .map(|i| op.compute_split(i, plain_log))
            .collect();

        let adjusted_lut = {
            let mut vec = vec![0; lut_input_size];
            for i in 0..lut_input_size {
                let lhs = i & ((1 << plain_log) - 1);
                let rhs = i >> plain_log;
                let masked_lhs = masking_chunk_msb(lhs, chunk_size, plain_log);
                let masked_rhs = masking_chunk_msb(rhs, chunk_size, plain_log);
                let masked_input = masked_lhs | (masked_rhs << plain_log);
                vec[i] = plain_lut[masked_input];
            }
            vec
        };

        for i in 0..lut_input_size {
            let lhs = i & ((1 << plain_log) - 1);
            let rhs = i >> plain_log;
            let masked_lhs = masking_chunk_msb(lhs, chunk_size, plain_log);
            let masked_rhs = masking_chunk_msb(rhs, chunk_size, plain_log);
            let masked_input = masked_lhs | (masked_rhs << plain_log);

            let from_adjusted_lut = adjusted_lut[i];
            let from_plain_lut_by_masked = plain_lut[masked_input];

            println!(
            "i: {:02x} (lhs: {:x}, rhs: {:x}), masked_lhs: {:x}, masked_rhs: {:x}, masked_input: {:02x} | adjusted: {} | plain_by_masked: {}",
            i, lhs, rhs, masked_lhs, masked_rhs, masked_input, from_adjusted_lut, from_plain_lut_by_masked
        );
            // 只校验adjusted_lut[i] == plain_lut[masked_input]
            assert_eq!(
                from_adjusted_lut, from_plain_lut_by_masked,
                "adjusted_lut[{i}] != plain_lut[masked_input={masked_input}]"
            );
        }
    }

    #[test]
    fn test_split_adjusted_lut_by_chunk() {
        let adjusted_lut = vec![0b1011_1100, 0b0001_0110, 0b1111_0000, 0b0101_1010];
        let plain_log = 8;
        let chunk_size = 4;
        let split = split_adjusted_lut_by_chunk(&adjusted_lut, plain_log, chunk_size);

        // 期望：
        // adjusted_lut[0]: 0b1011_1100  → [0b1100, 0b1011]
        // adjusted_lut[1]: 0b0001_0110  → [0b0110, 0b0001]
        // adjusted_lut[2]: 0b1111_0000  → [0b0000, 0b1111]
        // adjusted_lut[3]: 0b0101_1010  → [0b1010, 0b0101]
        assert_eq!(split[0], vec![0b1100, 0b0110, 0b0000, 0b1010]);
        assert_eq!(split[1], vec![0b1011, 0b0001, 0b1111, 0b0101]);
    }

    #[test]
    fn test_adjust_lut_with_masking_and_split() {
        let plain_log = 8;
        let chunk_size = 4;
        let input_bitwidths = vec![plain_log; 2];
        let op = ArithmeticOp::Add;

        // 1. 明文查找表
        let plain_lut = get_plain_lut(plain_log, &op);

        // 2. 自动生成掩码查找表
        let adjusted_lut = adjust_lut_with_masking(&plain_lut, &input_bitwidths, chunk_size);

        // 3. 手工生成掩码查找表（对比）
        let lut_input_size = 1 << (plain_log * 2);
        let mut manual_lut = Vec::with_capacity(lut_input_size);
        for i in 0..lut_input_size {
            let lhs = i & ((1 << plain_log) - 1);
            let rhs = i >> plain_log;
            let masked_lhs = masking_chunk_msb(lhs, chunk_size, plain_log);
            let masked_rhs = masking_chunk_msb(rhs, chunk_size, plain_log);
            let masked_input = masked_lhs | (masked_rhs << plain_log);
            manual_lut.push(plain_lut[masked_input]);
        }

        // 4. 两种掩码查找表内容应一致
        assert_eq!(
            adjusted_lut, manual_lut,
            "adjust_lut_with_masking does not match manual construction"
        );

        // 5. 拆分两个表，分chunk比对
        let split1 = split_adjusted_lut_by_chunk(&adjusted_lut, plain_log, chunk_size);
        let split2 = split_adjusted_lut_by_chunk(&manual_lut, plain_log, chunk_size);
        assert_eq!(split1, split2, "拆分后的chunk分表不一致");

        // 6. 检查每一项的拆分是否和人工bit拆分一致
        for (idx, &val) in adjusted_lut.iter().enumerate() {
            let segs = plain_log / chunk_size;
            for seg in 0..segs {
                let mask = (1 << chunk_size) - 1;
                let chunk = (val >> (seg * chunk_size)) & mask;
                assert_eq!(
                    chunk, split1[seg][idx],
                    "拆分chunk第{seg}块，表项{idx}，bit位不一致"
                );
            }
        }
    }
}
