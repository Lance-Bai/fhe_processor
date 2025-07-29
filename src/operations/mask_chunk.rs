pub fn masked_bit_extraction(input: usize, chunk_size: usize) -> Vec<usize> {
    let mut result = vec![0; chunk_size];
    for i in 0..chunk_size {
        let mut xor_sum = (input >> i) & 1;
        for j in (i + 1)..chunk_size {
            xor_sum ^= (input >> j) & 1;
        }
        result[i] = xor_sum;
    }
    result
}

pub fn masking_chunk_msb(input: usize, chunk_size: usize, total_bits: usize) -> usize {
    let num_chunks = (total_bits + chunk_size - 1) / chunk_size;
    let mut output = Vec::with_capacity(num_chunks * chunk_size);

    for chunk in 0..num_chunks {
        let shift = chunk * chunk_size;
        let bits_in_chunk = if shift + chunk_size > total_bits {
            total_bits - shift
        } else {
            chunk_size
        };
        let chunk_value = (input >> shift) & ((1 << bits_in_chunk) - 1);
        let chunk_encoded = masked_bit_extraction(chunk_value, bits_in_chunk);
        output.extend(chunk_encoded);
    }
    vec_to_usize(&output)
}

fn vec_to_usize(bits: &[usize]) -> usize {
    bits.iter()
        .enumerate()
        .fold(0, |acc, (i, &b)| acc | (b << i))
}
#[cfg(test)]
mod tests {
    use crate::operations::{
        operand::ArithmeticOp,
        plain_lut::{adjust_lut_with_masking, get_plain_lut, split_adjusted_lut_by_chunk},
    };

    use super::*;
    #[test]
    fn test_masking_chunk_msb() {
        let input = 0b1101_1101_1001_1101;
        let chunk_size = 4;
        let total_bits = 16;
        let output = masking_chunk_msb(input, chunk_size, total_bits);
        println!("{:b}->{:b}", input, output);
    }

    
}
