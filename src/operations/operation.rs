use crate::{
    operations::{
        cipher_lut::{self, generate_lut_from_vecs, tfhe_vertical_packing_lookup},
        lut,
        operand::ArithmeticOp,
        plain_lut::{
            build_split_lut_tables, build_split_lut_tables_cipher_plain,
            build_split_lut_tables_plain_cipher,
        },
    },
    processors::lwe_stored_ksk::LweStoredReusedKeyswitchKey,
};
use concrete_fft::c64;
use tfhe::core_crypto::prelude::{
    ComputationBuffers, Fft, FourierGgswCiphertextList, LweCiphertext, PolynomialList,
};
use tfhe::core_crypto::{fft_impl::fft64::crypto::wop_pbs::vertical_packing_scratch, prelude::*};
#[derive(Debug, Clone, Copy)]
pub enum OperandType {
    BothCipher,
    PlainCipher,
    CipherPlain,
}

pub struct Operation {
    // 操作类型和参数配置
    pub op: ArithmeticOp,
    pub op_type: OperandType,
    pub bit_width: usize,  //8,16,32
    pub chunk_size: usize, // 1,2,4
    // 只存密文查找表
    pub cipher_lut: Vec<PolynomialList<Vec<u64>>>,
}

impl Operation {
    pub fn new(
        op: ArithmeticOp,
        op_type: OperandType,
        bit_width: usize,
        chunk_size: usize,
        poly_size: tfhe::boolean::prelude::PolynomialSize,
        delta: u64,
        immediate: Option<usize>,
    ) -> Self {
        let plain_lut = match op_type {
            OperandType::BothCipher => {
                build_split_lut_tables(bit_width, vec![bit_width, bit_width], chunk_size, &op)
            }
            OperandType::PlainCipher => build_split_lut_tables_plain_cipher(
                bit_width,
                immediate.unwrap(),
                vec![bit_width],
                chunk_size,
                &op,
            ),
            OperandType::CipherPlain => build_split_lut_tables_cipher_plain(
                bit_width,
                immediate.unwrap(),
                vec![bit_width],
                chunk_size,
                &op,
            ),
        };

        let cipher_lut = generate_lut_from_vecs(&plain_lut, poly_size, delta);
        Self {
            op,
            op_type,
            bit_width,
            chunk_size,
            cipher_lut,
        }
    }

    /// 批量 vertical packing 查表操作
    ///
    /// # 参数
    /// - `ggsw_list`: 用户的 GGSW 密文数组
    /// - `fft`: FFT 上下文
    /// - `buffer`: 临时计算缓存
    /// - `lut_input_size`: 查找表输入位数
    /// - 返回查表结果密文数组
    pub fn vertical_packing_multi_lookup(
        &self,
        lwe_outs: &mut [LweCiphertext<Vec<u64>>],
        ggsw_list: &FourierGgswCiphertextList<Vec<c64>>,
        fft: &Fft,
        buffer: &mut ComputationBuffers,
    ) {
        let lut_input_size = match self.op_type {
            OperandType::BothCipher => self.bit_width * 2,
            OperandType::PlainCipher => self.bit_width,
            OperandType::CipherPlain => self.bit_width,
        };
        assert_eq!(
            lut_input_size,
            ggsw_list.count(),
            "lut_input_size = {}, ggsw_list.count()={}",
            lut_input_size,
            ggsw_list.count()
        );
        let lut = &self.cipher_lut[0];
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
        assert_eq!(self.cipher_lut.len(), lwe_outs.len());
        for (lut, lwe_out) in self.cipher_lut.iter().zip(lwe_outs.iter_mut()) {
            tfhe_vertical_packing_lookup(lut, lwe_out, ggsw_list, fft, buffer, lut_input_size);
        }
        
    }
}
