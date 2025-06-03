use aligned_vec::{ABox, ConstAlign};
use auto_base_conv::{
    automorphism::*, glwe_conv::*, glwe_preprocessing_assign, keyswitch_glwe_ciphertext,
    switch_scheme, utils::*, FourierGlweKeyswitchKey,
};
use std::collections::HashMap;
use tfhe::core_crypto::{
    fft_impl::fft64::
        c64
    ,
    prelude::*,
};

pub fn convert_to_ggsw_after_blind_rotate_4_bit<Scalar, InputCont, OutputCont>(
    glev_in: &GlweCiphertextList<InputCont>,
    ggsw_out: &mut GgswCiphertext<OutputCont>,
    bit_idx_from_msb: usize,
    glwe_ksk_to_large: &FourierGlweKeyswitchKey<ABox<[c64], ConstAlign<128>>>,
    glwe_ksk_from_large: &FourierGlweKeyswitchKey<ABox<[c64], ConstAlign<128>>>,
    auto_keys: &HashMap<usize, AutomorphKey<ABox<[c64]>>>,
    ss_key: &FourierGgswCiphertextList<ABox<[c64]>>,
    ciphertext_modulus: CiphertextModulus<Scalar>,
) where
    Scalar: UnsignedTorus,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    assert!(
        bit_idx_from_msb <= 3,
        "Multi-bit extraction is supported for at most 4 bits"
    );

    assert_eq!(glev_in.polynomial_size(), ggsw_out.polynomial_size());
    assert_eq!(glev_in.glwe_size(), ggsw_out.glwe_size());
    assert_eq!(glev_in.polynomial_size(), ss_key.polynomial_size());
    assert_eq!(glev_in.glwe_size(), ss_key.glwe_size());

    let glwe_size = glev_in.glwe_size();
    let polynomial_size = glev_in.polynomial_size();

    let cbs_level = ggsw_out.decomposition_level_count();
    let cbs_base_log = ggsw_out.decomposition_base_log();

    let large_lwe_dimension = LweDimension(glwe_size.to_glwe_dimension().0 * polynomial_size.0);
    let mut buf_lwe = LweCiphertext::new(
        Scalar::ZERO,
        large_lwe_dimension.to_lwe_size(),
        ciphertext_modulus,
    );
    let mut buf_large_glwe = GlweCiphertext::new(
        Scalar::ZERO,
        glwe_ksk_to_large.output_glwe_size(),
        polynomial_size,
        ciphertext_modulus,
    );

    let mut glev_out = GlweCiphertextList::new(
        Scalar::ZERO,
        glwe_size,
        polynomial_size,
        GlweCiphertextCount(cbs_level.0),
        ciphertext_modulus,
    );

    for (k, (mut glwe_out, glwe_in)) in glev_out.iter_mut().zip(glev_in.iter()).enumerate() {
        let cur_level = k + 1;
        let log_scale = Scalar::BITS - cur_level * cbs_base_log.0;
        let scale_offset = Plaintext(Scalar::ONE << (log_scale - 1));

        // 处理不同的bit索引情况
        match bit_idx_from_msb {
            0 => {
                // 直接提取，无需额外计算
                extract_and_adjust_lwe(&mut buf_lwe, &glwe_in, scale_offset);
            }

            1 => {
                // 第二位信息通过 1 XOR 2 提取
                process_second_bit(
                    &glwe_in,
                    &mut buf_lwe,
                    glwe_size,
                    polynomial_size,
                    ciphertext_modulus,
                );
            }

            2 => {
                // 第三位信息通过 1 XOR 2 XOR 3 提取
                process_third_bit(
                    &glwe_in,
                    &mut buf_lwe,
                    glwe_size,
                    polynomial_size,
                    ciphertext_modulus,
                );
            }

            3 => {
                // 第四位信息通过 1 XOR 2 XOR 3 XOR 4 提取
                process_fourth_bit(
                    &glwe_in,
                    &mut buf_lwe,
                    glwe_size,
                    polynomial_size,
                    ciphertext_modulus,
                );
            }

            _ => {
                // 这个分支永远不会到达，因为上面已经有断言检查
                unreachable!("bit_idx_from_msb should be <= 3");
            }
        }

        convert_lwe_to_glwe_const(&buf_lwe, &mut glwe_out);
        keyswitch_glwe_ciphertext(&glwe_ksk_to_large, &glwe_out, &mut buf_large_glwe);
        glwe_preprocessing_assign(&mut buf_large_glwe);
        trace_assign(&mut buf_large_glwe, &auto_keys);
        keyswitch_glwe_ciphertext(&glwe_ksk_from_large, &buf_large_glwe, &mut glwe_out);
    }

    switch_scheme(&glev_out, ggsw_out, ss_key.as_view());
}

// 辅助函数：提取并调整LWE样本
fn extract_and_adjust_lwe<Scalar, Cont>(
    buf_lwe: &mut LweCiphertext<Vec<Scalar>>,
    glwe_source: &GlweCiphertext<Cont>,
    scale_offset: Plaintext<Scalar>,
) where
    Scalar: UnsignedTorus,
    Cont: Container<Element = Scalar>,
{
    extract_lwe_sample_from_glwe_ciphertext(glwe_source, buf_lwe, MonomialDegree(0));
    lwe_ciphertext_plaintext_add_assign(buf_lwe, scale_offset);
}

// 辅助函数：处理第二位
fn process_second_bit<Scalar, InputCont>(
    glwe_in: &GlweCiphertext<InputCont>,
    buf_lwe: &mut LweCiphertext<Vec<Scalar>>,
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    ciphertext_modulus: CiphertextModulus<Scalar>,
) where
    Scalar: UnsignedTorus,
    InputCont: Container<Element = Scalar>,
{
    // [0 0 0 1]
    //  0 1 2 3  index
    let unit = polynomial_size.0 / 2; // N/2
    let mut glwe_out =
        GlweCiphertext::new(Scalar::ZERO, glwe_size, polynomial_size, ciphertext_modulus);
    glwe_ciphertext_monic_monomial_mul(&mut glwe_out, glwe_in, MonomialDegree(3 * unit));
    extract_and_adjust_lwe(
        buf_lwe,
        &glwe_out,
        Plaintext(Scalar::ONE << (Scalar::BITS - 1)),
    );
}

// 辅助函数：处理第三位
fn process_third_bit<Scalar, InputCont>(
    glwe_in: &GlweCiphertext<InputCont>,
    buf_lwe: &mut LweCiphertext<Vec<Scalar>>,
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    ciphertext_modulus: CiphertextModulus<Scalar>,
) where
    Scalar: UnsignedTorus,
    InputCont: Container<Element = Scalar>,
{
    // [ 1  0  0  0  0  1  0 -1]
    //   0  1  2  3  4  5  6  7   index
    let unit = polynomial_size.0 / 4; // N/4
    let mut glwe_out =
        GlweCiphertext::new(Scalar::ZERO, glwe_size, polynomial_size, ciphertext_modulus);
    let mut mid1 =
        GlweCiphertext::new(Scalar::ZERO, glwe_size, polynomial_size, ciphertext_modulus);
    let mut mid2 =
        GlweCiphertext::new(Scalar::ZERO, glwe_size, polynomial_size, ciphertext_modulus);

    glwe_ciphertext_monic_monomial_mul(&mut glwe_out, glwe_in, MonomialDegree(0));
    glwe_ciphertext_monic_monomial_mul(&mut mid1, glwe_in, MonomialDegree(5 * unit));
    glwe_ciphertext_monic_monomial_mul(&mut mid2, glwe_in, MonomialDegree(7 * unit));

    glwe_ciphertext_add_assign(&mut glwe_out, &mid1);
    glwe_ciphertext_sub_assign(&mut glwe_out, &mid2);

    extract_and_adjust_lwe(
        buf_lwe,
        &glwe_out,
        Plaintext(Scalar::ONE << (Scalar::BITS - 1)),
    );
}

fn process_fourth_bit<Scalar, InputCont>(
    glwe_in: &GlweCiphertext<InputCont>,
    buf_lwe: &mut LweCiphertext<Vec<Scalar>>,
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    ciphertext_modulus: CiphertextModulus<Scalar>,
) where
    Scalar: UnsignedTorus,
    InputCont: Container<Element = Scalar>,
{
    // [ 0  0  0  1  0  0  0 -1  0  1  0  0  1 -1  0  0]
    //   0  1  2  3  4  5  6  7  8  9  10 11 12 13 14 15   index
    let unit = polynomial_size.0 / 8; // N/8
    let mut glwe_out =
        GlweCiphertext::new(Scalar::ZERO, glwe_size, polynomial_size, ciphertext_modulus);
    let mut mid1 =
        GlweCiphertext::new(Scalar::ZERO, glwe_size, polynomial_size, ciphertext_modulus);
    let mut mid2 =
        GlweCiphertext::new(Scalar::ZERO, glwe_size, polynomial_size, ciphertext_modulus);
    let mut mid3 =
        GlweCiphertext::new(Scalar::ZERO, glwe_size, polynomial_size, ciphertext_modulus);
    let mut mid4 =
        GlweCiphertext::new(Scalar::ZERO, glwe_size, polynomial_size, ciphertext_modulus);

    glwe_ciphertext_monic_monomial_mul(&mut glwe_out, glwe_in, MonomialDegree(3 * unit));
    glwe_ciphertext_monic_monomial_mul(&mut mid1, glwe_in, MonomialDegree(7 * unit));
    glwe_ciphertext_monic_monomial_mul(&mut mid2, glwe_in, MonomialDegree(9 * unit));
    glwe_ciphertext_monic_monomial_mul(&mut mid3, glwe_in, MonomialDegree(12 * unit));
    glwe_ciphertext_monic_monomial_mul(&mut mid4, glwe_in, MonomialDegree(13 * unit));

    glwe_ciphertext_sub_assign(&mut glwe_out, &mid1);
    glwe_ciphertext_add_assign(&mut glwe_out, &mid2);
    glwe_ciphertext_add_assign(&mut glwe_out, &mid3);
    glwe_ciphertext_sub_assign(&mut glwe_out, &mid4);

    extract_and_adjust_lwe(
        buf_lwe,
        &glwe_out,
        Plaintext(Scalar::ONE << (Scalar::BITS - 1)),
    );
}
