use std::clone;

use concrete_fft::c64;
use itertools::Itertools;
use tfhe::{
    core_crypto::{
        fft_impl::fft64::crypto::ggsw::{cmux, cmux_scratch},
        prelude::{
            cmux_assign_mem_optimized, cmux_assign_mem_optimized_requirement,
            extract_lwe_sample_from_glwe_ciphertext, plaintext, trivially_encrypt_glwe_ciphertext,
            trivially_encrypt_lwe_ciphertext, ComputationBuffers, ContiguousEntityContainer,
            ContiguousEntityContainerMut, Fft, FourierGgswCiphertext, FourierGgswCiphertextList,
            GlweCiphertext, GlweCiphertextCount, GlweCiphertextList, LweCiphertext, MonomialDegree,
            Plaintext, PlaintextList,
        },
    },
    shortint::wopbs::PlaintextCount,
};

use crate::operations::operand::ArithmeticOp;

pub fn opmized_compare(
    input: &Vec<FourierGgswCiphertextList<Vec<c64>>>,
    lwe_outs: &mut [LweCiphertext<Vec<u64>>],
    op: ArithmeticOp,
    fft: &Fft,
) {
    let glwe_size = input[0].glwe_size();
    let poly_size = input[0].polynomial_size();
    let cipher_modulus = lwe_outs[0].ciphertext_modulus();

    let mut equiv = GlweCiphertext::new(0, glwe_size, poly_size, cipher_modulus);
    let mut greater = equiv.clone();
    let mut less = equiv.clone();

    let mut equiv_xx0 = equiv.clone();
    let mut equiv_xx1 = equiv.clone();
    let mut equiv_x0 = equiv.clone();
    let mut equiv_x1 = equiv.clone();
    let mut equiv_0 = equiv.clone();
    let mut equiv_1 = equiv.clone();
    let mut mid_1 = equiv.clone();
    let mut mid_0 = equiv.clone();

    let encoded_msg_1 = 1_u64 << 60;
    let plaintext_list_1 = PlaintextList::new(encoded_msg_1, PlaintextCount(poly_size.0));
    let plaintext_list_0 = PlaintextList::new(0, PlaintextCount(poly_size.0));
    match op {
        ArithmeticOp::GT => {
            trivially_encrypt_glwe_ciphertext(&mut greater, &plaintext_list_1);
            trivially_encrypt_glwe_ciphertext(&mut equiv, &plaintext_list_0);
            trivially_encrypt_glwe_ciphertext(&mut less, &plaintext_list_0);
        }
        ArithmeticOp::GTE => {
            trivially_encrypt_glwe_ciphertext(&mut greater, &plaintext_list_1);
            trivially_encrypt_glwe_ciphertext(&mut equiv, &plaintext_list_1);
            trivially_encrypt_glwe_ciphertext(&mut less, &plaintext_list_0);
        }
        ArithmeticOp::LT => {
            trivially_encrypt_glwe_ciphertext(&mut greater, &plaintext_list_0);
            trivially_encrypt_glwe_ciphertext(&mut equiv, &plaintext_list_0);
            trivially_encrypt_glwe_ciphertext(&mut less, &plaintext_list_1);
        }
        ArithmeticOp::LTE => {
            trivially_encrypt_glwe_ciphertext(&mut greater, &plaintext_list_0);
            trivially_encrypt_glwe_ciphertext(&mut less, &plaintext_list_1);
            trivially_encrypt_glwe_ciphertext(&mut equiv, &plaintext_list_1);
        }
        ArithmeticOp::EQ => {
            trivially_encrypt_glwe_ciphertext(&mut greater, &plaintext_list_0);
            trivially_encrypt_glwe_ciphertext(&mut equiv, &plaintext_list_1);
            trivially_encrypt_glwe_ciphertext(&mut less, &plaintext_list_0);
        }
        _ => {}
    }

    let list_a = &input[0];
    let list_b = &input[1];
    let fft_viwe = fft.as_view();
    let mut buffer = ComputationBuffers::new();
    let buffer_size_req =
        cmux_assign_mem_optimized_requirement::<u64>(glwe_size, poly_size, fft_viwe)
            .unwrap()
            .unaligned_bytes_required();

    buffer.resize(buffer_size_req);

    for (index, (a, b)) in list_a
        .as_view()
        .into_ggsw_iter()
        .rev()
        .zip(list_b.as_view().into_ggsw_iter().rev())
        .enumerate()
    {
        match index % 4 {
            0 => {
                local_cmux(&less, &equiv, &b, &mut mid_1, &mut buffer, fft);
                local_cmux(&equiv, &greater, &b, &mut mid_0, &mut buffer, fft);
                local_cmux(&mid_0, &mid_1, &a, &mut equiv_xx1, &mut buffer, fft);

                local_cmux(&greater, &equiv, &b, &mut mid_1, &mut buffer, fft);
                local_cmux(&equiv, &less, &b, &mut mid_0, &mut buffer, fft);
                local_cmux(&mid_0, &mid_1, &a, &mut equiv_xx0, &mut buffer, fft);
            }
            1 => {
                local_cmux(&less, &equiv_xx1, &b, &mut mid_1, &mut buffer, fft);
                local_cmux(&equiv_xx0, &greater, &b, &mut mid_0, &mut buffer, fft);
                local_cmux(&mid_0, &mid_1, &a, &mut equiv_x1, &mut buffer, fft);

                local_cmux(&greater, &equiv_xx1, &b, &mut mid_1, &mut buffer, fft);
                local_cmux(&equiv_xx0, &less, &b, &mut mid_0, &mut buffer, fft);
                local_cmux(&mid_0, &mid_1, &a, &mut equiv_x0, &mut buffer, fft);
            }
            2 => {
                local_cmux(&less, &equiv_x1, &b, &mut mid_1, &mut buffer, fft);
                local_cmux(&equiv_x0, &greater, &b, &mut mid_0, &mut buffer, fft);
                local_cmux(&mid_0, &mid_1, &a, &mut equiv_1, &mut buffer, fft);

                local_cmux(&greater, &equiv_x1, &b, &mut mid_1, &mut buffer, fft);
                local_cmux(&equiv_x0, &less, &b, &mut mid_0, &mut buffer, fft);
                local_cmux(&mid_0, &mid_1, &a, &mut equiv_0, &mut buffer, fft);
            }

            3 => {
                local_cmux(&greater, &equiv_1, &b, &mut mid_1, &mut buffer, fft);
                local_cmux(&equiv_0, &less, &b, &mut mid_0, &mut buffer, fft);
                local_cmux(&mid_0, &mid_1, &a, &mut equiv, &mut buffer, fft);
            }
            _ => {
                // not used
            }
        }
    }
    for lwe in lwe_outs.iter_mut() {
        trivially_encrypt_lwe_ciphertext(lwe, Plaintext(0));
    }
    let result = lwe_outs.last_mut().unwrap();
    extract_lwe_sample_from_glwe_ciphertext(&equiv, result, MonomialDegree(0));
}


fn local_cmux(
    input_0: &GlweCiphertext<Vec<u64>>,
    input_1: &GlweCiphertext<Vec<u64>>,
    control: &FourierGgswCiphertext<&[c64]>,
    mut output: &mut GlweCiphertext<Vec<u64>>,
    buffer: &mut ComputationBuffers,
    fft: &Fft,
) {
    let mut temp = input_1.clone();
    *output = input_0.clone();
    let stack = buffer.stack();
    let fft_view = fft.as_view();
    cmux_assign_mem_optimized(&mut output, &mut temp, control, fft_view, stack);
}
