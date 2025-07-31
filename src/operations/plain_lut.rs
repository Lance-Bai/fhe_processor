use crate::operations::{
    mask_chunk::{masking_chunk_msb, masking_chunk_msb_decode},
    operand::ArithmeticOp,
};

/// 生成一个查找表，每个表项是完整plain_log位宽的运算结果
pub fn get_plain_cipher_cipher(plain_log: usize, op: &ArithmeticOp) -> Vec<usize> {
    let lut_input_size: usize = 1 << (plain_log * 2);
    let mut lut = Vec::with_capacity(lut_input_size);

    for i in 0..lut_input_size {
        let result = op.compute_split(i, plain_log);
        lut.push(result);
    }
    lut
}

pub fn get_plain_lut_cipher_plain(
    plain_log: usize,
    immediate: usize,
    op: &ArithmeticOp,
) -> Vec<usize> {
    let lut_input_size: usize = 1 << (plain_log);
    let mut lut = Vec::with_capacity(lut_input_size);

    for i in 0..lut_input_size {
        let result = op.compute_cipher_plain(i, immediate, plain_log);
        lut.push(result);
    }
    lut
}

pub fn get_plain_lut_plain_cipher(
    plain_log: usize,
    immediate: usize,
    op: &ArithmeticOp,
) -> Vec<usize> {
    let lut_input_size: usize = 1 << (plain_log);
    let mut lut = Vec::with_capacity(lut_input_size);

    for i in 0..lut_input_size {
        let result = op.compute_plain_cipher(i, immediate, plain_log);
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

/// 使用解码版的 adjust_lut_with_masking
///
/// plain_lut: 明文查找表
/// input_bitwidths: 各输入的bit宽数组
/// chunk_size: 掩码分块宽度
///
/// 返回：解码后的查找表
pub fn adjust_lut_with_masking_decode(
    plain_lut: &[usize],
    input_bitwidths: &[usize],
    chunk_size: usize,
) -> Vec<usize> {
    let total_bits: usize = input_bitwidths.iter().sum();
    let lut_input_size = 1 << total_bits;
    (0..lut_input_size)
        .map(|masked_input| {
            // 拆分每个输入块的掩码值
            let mut blocks = Vec::with_capacity(input_bitwidths.len());
            let mut acc = masked_input;
            for &bits in input_bitwidths {
                blocks.push(acc & ((1 << bits) - 1));
                acc >>= bits;
            }
            // 对每个block做解码
            let mut decoded_input = 0usize;
            let mut offset = 0;
            for (masked_block, &bits) in blocks.iter().zip(input_bitwidths) {
                let plain_block = masking_chunk_msb_decode(*masked_block, chunk_size, bits);
                decoded_input |= plain_block << offset;
                offset += bits;
            }
            // 查明文表
            plain_lut[decoded_input]
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
    let plain_lut = get_plain_cipher_cipher(plain_log, op);

    // 2. 掩码调整
    let adjusted_lut = adjust_lut_with_masking_decode(&plain_lut, &input_bitwidths, chunk_size);

    // 3. 拆分为chunk分表
    split_adjusted_lut_by_chunk(&adjusted_lut, plain_log, chunk_size)
}

pub fn build_split_lut_tables_cipher_plain(
    plain_log: usize,
    immediate: usize,
    input_bitwidths: Vec<usize>,
    chunk_size: usize,
    op: &ArithmeticOp,
) -> Vec<Vec<usize>> {
    // 1. 生成明文查找表
    let plain_lut = get_plain_lut_cipher_plain(plain_log, immediate, op);

    // 2. 掩码调整
    let adjusted_lut = adjust_lut_with_masking_decode(&plain_lut, &input_bitwidths, chunk_size);

    // 3. 拆分为chunk分表
    split_adjusted_lut_by_chunk(&adjusted_lut, plain_log, chunk_size)
}

pub fn build_split_lut_tables_plain_cipher(
    plain_log: usize,
    immediate: usize,
    input_bitwidths: Vec<usize>,
    chunk_size: usize,
    op: &ArithmeticOp,
) -> Vec<Vec<usize>> {
    // 1. 生成明文查找表
    let plain_lut = get_plain_lut_plain_cipher(plain_log, immediate, op);

    // 2. 掩码调整
    let adjusted_lut = adjust_lut_with_masking_decode(&plain_lut, &input_bitwidths, chunk_size);

    // 3. 拆分为chunk分表
    split_adjusted_lut_by_chunk(&adjusted_lut, plain_log, chunk_size)
}

#[cfg(test)]
mod tests {
    use crate::operations::mask_chunk::usize_to_vec;

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
    fn test_masking_chunk_encode_decode() {
        for &chunk_size in &[1, 2, 4] {
            for &bits in &[8] {
                println!("==== chunk_size: {}, bits: {} ====", chunk_size, bits);
                let cases = (1 << bits);
                for v in 0..cases {
                    let encoded = masking_chunk_msb(v, chunk_size, bits);
                    let decoded = masking_chunk_msb_decode(encoded, chunk_size, bits);
                    if decoded != v {
                        // 展开原始、编码后、解码后 bit 向量对比
                        let orig_bits = usize_to_vec(v, bits);
                        let encoded_bits = usize_to_vec(encoded, bits); // 注意这里encoded实际长度可不同
                        let decoded_bits = usize_to_vec(decoded, bits);
                        println!("!!! MISMATCH !!!");
                        println!("v         = {} ({:b})", v, v);
                        println!("encoded   = {} ({:b})", encoded, encoded);
                        println!("decoded   = {} ({:b})", decoded, decoded);
                        println!("orig_bits    = {:?}", orig_bits);
                        println!("encoded_bits = {:?}", encoded_bits);
                        println!("decoded_bits = {:?}", decoded_bits);
                        panic!(
                            "Fail: v={}, chunk_size={}, bits={}, encoded={}, decoded={}",
                            v, chunk_size, bits, encoded, decoded
                        );
                    } else if v == 0 || v == cases - 1 {
                        // 打印首末几个示例，便于肉眼核查
                        println!("OK: v={}, encoded={}, decoded={}", v, encoded, decoded);
                    }
                }
            }
        }
        println!("All masking_chunk_msb encode/decode tests passed!");
    }

    #[test]
    fn test_adjust_lut_with_masking_decode() {
        let input_bitwidths = vec![8, 8];
        let chunk_size = 4;
        // 构造一个明文查找表 plain_lut[i] = i
        let total_bits: usize = input_bitwidths.iter().sum();
        let plain_lut: Vec<usize> = (0..(1 << total_bits)).collect();
        let masked_lut = adjust_lut_with_masking_decode(&plain_lut, &input_bitwidths, chunk_size);
        // 验证逆向性
        for (i, &v) in masked_lut.iter().enumerate() {
            let mut blocks = Vec::with_capacity(input_bitwidths.len());
            let mut acc = i;
            for &bits in &input_bitwidths {
                blocks.push(acc & ((1 << bits) - 1));
                acc >>= bits;
            }
            let mut decoded_input = 0usize;
            let mut offset = 0;
            for (masked_block, &bits) in blocks.iter().zip(&input_bitwidths) {
                let plain_block = masking_chunk_msb_decode(*masked_block, chunk_size, bits);
                decoded_input |= plain_block << offset;
                offset += bits;
            }
            assert_eq!(v, plain_lut[decoded_input]);
        }
    }
}
