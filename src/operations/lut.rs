// use refined_tfhe_lhe::glwe_ciphertext_monic_monomial_div_assign;
// use concrete_fft::c64;
// use tfhe::{
//     boolean::prelude::PolynomialSize,
//     core_crypto::prelude::{
//         allocate_and_trivially_encrypt_new_glwe_ciphertext, cmux_assign,
//         extract_lwe_sample_from_glwe_ciphertext, CastFrom, CastInto, CiphertextModulus, Container,
//         ContainerMut, FourierGgswCiphertextList, GlweCiphertextOwned, GlweSize, LweCiphertext,
//         MonomialDegree, PlaintextList, UnsignedTorus,
//     },
// };

// use crate::operations::lut_manager::{ArithmeticLookupManager, ArithmeticOp};

// pub fn generate_8_to_8_lut<Scalar>(
//     plain_lut_low: &Vec<Scalar>,
//     plain_lut_high: &Vec<Scalar>,
//     polynomial_size: PolynomialSize,
//     glwe_size: GlweSize,
//     ciphertext_modulus: CiphertextModulus<Scalar>,
// ) -> GlweCiphertextOwned<Scalar>
// where
//     Scalar: UnsignedTorus + CastInto<usize>,
// {
//     // |---high---|---low---|---000---|
//     // |  0-255   | 256-511 | 512-end |
//     assert!(
//         plain_lut_low.len() == 256 && plain_lut_high.len() == 256,
//         "LUTs must have 256 entries"
//     );
//     assert!(
//         polynomial_size.0 >= 512,
//         "Polynomial size must be at least 512 for 8-to-8 LUT"
//     );
//     let delta = Scalar::ONE << 60;

//     let accumulator = (0..polynomial_size.0)
//         .map(|i| {
//             if i < 256 {
//                 plain_lut_high[i] * delta
//             } else if i < 512 {
//                 plain_lut_low[i - 256] * delta
//             } else {
//                 Scalar::ZERO
//             }
//         })
//         .collect::<Vec<Scalar>>();
//     let accumulator_plaintext = PlaintextList::from_container(accumulator);
//     let accumulator = allocate_and_trivially_encrypt_new_glwe_ciphertext(
//         glwe_size,
//         &accumulator_plaintext,
//         ciphertext_modulus,
//     );

//     accumulator
// }

// pub fn table_look_up_8_to_8<Scalar>(
//     input_low: &FourierGgswCiphertextList<Vec<c64>>,
//     input_high: &FourierGgswCiphertextList<Vec<c64>>,
//     accumulator: &mut GlweCiphertextOwned<Scalar>,
// ) where
//     Scalar: UnsignedTorus + CastInto<usize>,
// {
//     for (bit_idx, fourier_ggsw) in input_high.as_view().into_ggsw_iter().enumerate() {
//         let mut buf = accumulator.clone();
//         glwe_ciphertext_monic_monomial_div_assign(&mut buf, MonomialDegree(1 << (7 - bit_idx)));
//         cmux_assign(accumulator, &mut buf, &fourier_ggsw);
//     }
//     for (bit_idx, fourier_ggsw) in input_low.as_view().into_ggsw_iter().enumerate() {
//         let mut buf = accumulator.clone();
//         glwe_ciphertext_monic_monomial_div_assign(&mut buf, MonomialDegree(1 << (3 - bit_idx)));
//         cmux_assign(accumulator, &mut buf, &fourier_ggsw);
//     }
// }

// pub fn single_operator_calculate<Scalar, OutputCont>(
//     input_low: &FourierGgswCiphertextList<Vec<c64>>,
//     input_high: &FourierGgswCiphertextList<Vec<c64>>,
//     input_plain: u8,
//     output_low: &mut LweCiphertext<OutputCont>,
//     output_high: &mut LweCiphertext<OutputCont>,
//     manager: &ArithmeticLookupManager<Scalar>,
//     op: ArithmeticOp,
//     polynomial_size: PolynomialSize,
//     glwe_size: GlweSize,
//     ciphertext_modulus: CiphertextModulus<Scalar>,
// ) where
//     Scalar: UnsignedTorus + CastInto<usize> + CastFrom<u64>,
//     OutputCont: ContainerMut<Element = Scalar>,
// {
//     let plain_table = manager.get_subtable(op, input_plain).unwrap();
//     let low_vec = plain_table.get_low_nibble_subtable().to_vec();
//     let high_vec = plain_table.get_high_nibble_subtable().to_vec();
//     // println!("LUT low: {:?}, high: {:?}", low_vec, high_vec);

//     let mut accumulator = generate_8_to_8_lut(
//         &low_vec,
//         &high_vec,
//         polynomial_size,
//         glwe_size,
//         ciphertext_modulus,
//     );

//     table_look_up_8_to_8(input_low, input_high, &mut accumulator);
//     extract_lwe_sample_from_glwe_ciphertext(&accumulator, output_high, MonomialDegree(0));
//     extract_lwe_sample_from_glwe_ciphertext(&accumulator, output_low, MonomialDegree(256));
// }

// #[cfg(test)]
// mod tests {
//     use std::ops::Add;

//     use crate::operations::lut_manager::encode_special_byte;
//     use crate::utils::instance::ZeroNoiseTest;

//     use super::*;
//     use tfhe::boolean::prelude::{
//         DecompositionBaseLog, DecompositionLevelCount, PolynomialSize, StandardDev,
//     };
//     use tfhe::core_crypto::prelude::{
//         allocate_and_encrypt_new_lwe_ciphertext, allocate_and_generate_new_binary_glwe_secret_key,
//         convert_standard_ggsw_ciphertext_to_fourier, decrypt_lwe_ciphertext,
//         encrypt_constant_ggsw_ciphertext, ActivatedRandomGenerator, ContiguousEntityContainer,
//         ContiguousEntityContainerMut, EncryptionRandomGenerator, GgswCiphertextCount,
//         GgswCiphertextList, GlweSecretKey, Plaintext, SecretRandomGenerator,
//     };
//     use tfhe::core_crypto::seeders::new_seeder;

//     fn encrypt_4_fourier_ggsw_ciphertext(
//         msg: &[u64],
//         glwe_size: GlweSize,
//         polynomial_size: PolynomialSize,
//         ciphertext_modulus: CiphertextModulus<u64>,
//         cbs_base_log: DecompositionBaseLog,
//         cbs_level: DecompositionLevelCount,
//         glwe_secret_key: &GlweSecretKey<Vec<u64>>,
//         glwe_modular_std_dev: StandardDev,
//         mut encryption_generator: &mut EncryptionRandomGenerator<ActivatedRandomGenerator>,
//     ) -> FourierGgswCiphertextList<Vec<c64>> {
//         let mut ggsw_list = GgswCiphertextList::new(
//             0u64,
//             glwe_size,
//             polynomial_size,
//             cbs_base_log,
//             cbs_level,
//             GgswCiphertextCount(4),
//             ciphertext_modulus,
//         );
//         for (bit, mut ggsw) in msg.iter().zip(ggsw_list.iter_mut()) {
//             encrypt_constant_ggsw_ciphertext(
//                 &glwe_secret_key,
//                 &mut ggsw,
//                 Plaintext(*bit as u64),
//                 glwe_modular_std_dev,
//                 &mut encryption_generator,
//             );
//         }

//         let mut fourier_ggsw_list = FourierGgswCiphertextList::new(
//             vec![
//                 c64::default();
//                 4 * polynomial_size.to_fourier_polynomial_size().0
//                     * glwe_size.0
//                     * glwe_size.0
//                     * cbs_level.0
//             ],
//             4,
//             glwe_size,
//             polynomial_size,
//             cbs_base_log,
//             cbs_level,
//         );
//         for (mut fourier_ggsw, ggsw) in fourier_ggsw_list
//             .as_mut_view()
//             .into_ggsw_iter()
//             .zip(ggsw_list.iter())
//         {
//             convert_standard_ggsw_ciphertext_to_fourier(&ggsw, &mut fourier_ggsw);
//         }
//         fourier_ggsw_list
//     }
//     #[test]
//     fn test_table_look_up_8_to_8() {
//         let param = &ZeroNoiseTest;
//         let glwe_size = param.glwe_dimension().to_glwe_size();
//         let polynomial_size = param.polynomial_size();
//         let ciphertext_modulus = param.ciphertext_modulus();
//         let cbs_base_log = param.cbs_base_log();
//         let cbs_level = param.cbs_level();
//         let glwe_dimension = param.glwe_dimension();
//         let glwe_modular_std_dev = param.glwe_modular_std_dev();

//         let mut manager = ArithmeticLookupManager::<u64>::new();
//         manager.add_operation(ArithmeticOp::Addi);
//         manager.add_operation(ArithmeticOp::Mulli);
//         let plain_table = manager.get_subtable(ArithmeticOp::Mulli, 3).unwrap();
//         let low_vec = plain_table.get_low_nibble_subtable().to_vec();
//         let high_vec = plain_table.get_high_nibble_subtable().to_vec();
//         // println!("LUT low: {:?}\nhigh: {:?}", low_vec, high_vec);

//         let lut = generate_8_to_8_lut(
//             &low_vec,
//             &high_vec,
//             polynomial_size,
//             glwe_size,
//             ciphertext_modulus,
//         );

//         // Set random generators and buffers
//         let mut boxed_seeder = new_seeder();
//         let seeder = boxed_seeder.as_mut();

//         let mut secret_generator =
//             SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
//         let mut encryption_generator =
//             EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);

//         let glwe_sk = allocate_and_generate_new_binary_glwe_secret_key(
//             glwe_dimension,
//             polynomial_size,
//             &mut secret_generator,
//         );

//         let mut out_low = allocate_and_encrypt_new_lwe_ciphertext(
//             &glwe_sk.as_lwe_secret_key(),
//             Plaintext(0),
//             param.lwe_modular_std_dev(),
//             ciphertext_modulus,
//             &mut encryption_generator,
//         );
//         let mut out_high = allocate_and_encrypt_new_lwe_ciphertext(
//             &glwe_sk.as_lwe_secret_key(),
//             Plaintext(0),
//             param.lwe_modular_std_dev(),
//             ciphertext_modulus,
//             &mut encryption_generator,
//         );

//         for i in 0u8..=255 {
//             let (high_bits, low_bits) = encode_special_byte(i);
//             println!(
//                 "Input: {} -> {:08b} -> {:?}_{:?}",
//                 i, i, high_bits, low_bits
//             );
//             let mut combined: u8 = 0;
//             for i in 0..4 {
//                 combined ^= (high_bits[i] as u8) << (7 - i);
//                 combined ^= (low_bits[i] as u8) << (3 - i);
//             }
//             println!(
//                 "plain table result: tab[{}] = {:04b}_{:04b}",
//                 combined, high_vec[combined as usize], low_vec[combined as usize]
//             );
//             let low_gsw = encrypt_4_fourier_ggsw_ciphertext(
//                 &low_bits,
//                 glwe_size,
//                 polynomial_size,
//                 ciphertext_modulus,
//                 cbs_base_log,
//                 cbs_level,
//                 &glwe_sk,
//                 glwe_modular_std_dev,
//                 &mut encryption_generator,
//             );
//             let high_gsw = encrypt_4_fourier_ggsw_ciphertext(
//                 &high_bits,
//                 glwe_size,
//                 polynomial_size,
//                 ciphertext_modulus,
//                 cbs_base_log,
//                 cbs_level,
//                 &glwe_sk,
//                 glwe_modular_std_dev,
//                 &mut encryption_generator,
//             );
//             let mut accumulator = lut.clone();
//             table_look_up_8_to_8(&low_gsw, &high_gsw, &mut accumulator);

//             extract_lwe_sample_from_glwe_ciphertext(&accumulator, &mut out_high, MonomialDegree(0));
//             extract_lwe_sample_from_glwe_ciphertext(
//                 &accumulator,
//                 &mut out_low,
//                 MonomialDegree(256),
//             );
//             let low = decrypt_lwe_ciphertext(&glwe_sk.as_lwe_secret_key(), &out_low);
//             let high = decrypt_lwe_ciphertext(&glwe_sk.as_lwe_secret_key(), &out_high);
//             println!(
//                 "Output: {:04b}_{:04b} -> {}\n",
//                 (((high.0 >> 59) + 1) >> 1) % 256,
//                 (((low.0 >> 59) + 1) >> 1) % 256,
//                 16 * (((high.0 >> 59) + 1) >> 1) % 256 + (((low.0 >> 59) + 1) >> 1) % 256
//             );
//         }
//     }
// }
