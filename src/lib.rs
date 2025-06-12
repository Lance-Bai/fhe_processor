pub mod operations;
pub mod processors;
pub mod utils;

#[cfg(test)]
mod keyswitch_tests {
    use super::*;
    use crate::processors::{
        key_gen::allocate_and_generate_new_reused_lwe_key,
        lwe_stored_ksk::allocate_and_generate_new_stored_reused_lwe_keyswitch_key,
    };
    use rayon::{
        iter::{IntoParallelIterator, ParallelIterator},
        ThreadPoolBuilder,
    };
    use tfhe::core_crypto::prelude::*;

    fn keyswitch_trial() -> bool {
        let input_lwe_dimension = LweDimension(2048);
        let lwe_modular_std_dev =
            StandardDev(0.0000000000000000000000000000000000000000000000000000000000000001);
        let output_lwe_dimension = LweDimension(700);
        let decomp_base_log = DecompositionBaseLog(5);
        let decomp_level_count = DecompositionLevelCount(3);
        let ciphertext_modulus = CiphertextModulus::<u64>::new_native();

        let mut seeder = new_seeder();
        let seeder = seeder.as_mut();
        let mut encryption_generator =
            EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);
        let mut secret_generator =
            SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());

        let input_lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key(
            input_lwe_dimension,
            &mut secret_generator,
        );
        let output_lwe_secret_key =
            allocate_and_generate_new_reused_lwe_key(&input_lwe_secret_key, output_lwe_dimension);
        let ksk = allocate_and_generate_new_stored_reused_lwe_keyswitch_key(
            &input_lwe_secret_key,
            &output_lwe_secret_key,
            decomp_base_log,
            decomp_level_count,
            lwe_modular_std_dev,
            ciphertext_modulus,
            &mut encryption_generator,
        );

        let msg = 5u64;
        let plaintext = Plaintext(msg << 60);

        let lwe = allocate_and_encrypt_new_lwe_ciphertext(
            &input_lwe_secret_key,
            plaintext,
            lwe_modular_std_dev,
            ciphertext_modulus,
            &mut encryption_generator,
        );

        let mut output_lwe =
            LweCiphertext::new(0u64, output_lwe_dimension.to_lwe_size(), ciphertext_modulus);

        processors::lwe_storede_ks::stored_reused_keyswitch_lwe_ciphertext(
            &ksk,
            &lwe,
            &mut output_lwe,
        );

        let decrypted_plaintext = decrypt_lwe_ciphertext(&output_lwe_secret_key, &output_lwe);

        let decomposer = SignedDecomposer::new(DecompositionBaseLog(4), DecompositionLevelCount(1));
        let rounded = decomposer.closest_representable(decrypted_plaintext.0);
        let cleartext = rounded >> 60;

        cleartext == msg
    }

    #[test]
    fn it_works_multiple_times() {
        // 限制最大并行线程数为 4（你可以根据机器内存调整）
        ThreadPoolBuilder::new()
            .num_threads(8)
            .build_global()
            .unwrap();

        let trials = 10;
        let success = (0..trials)
            .into_par_iter()
            .map(|_| keyswitch_trial())
            .filter(|&ok| ok)
            .count();

        println!(
            "Keyswitch success rate: {}/{} = {:.3}%",
            success,
            trials,
            (success as f64) * 100.0 / (trials as f64)
        );
        assert!(success > 0, "No successful keyswitches!");
    }
}

#[cfg(test)]
mod circuit_bootstrapping_tests {
    use crate::{
        processors::{
            cbs_4_bits::circuit_bootstrapping_4_bits_at_once,
            key_gen::allocate_and_generate_new_reused_lwe_key,
            low_noise_ms::fast_low_noise_pbs_modulus_switch,
            lwe_stored_ksk::allocate_and_generate_new_stored_reused_lwe_keyswitch_key,
        },
        utils::instance::{Processor_4_bits, ZeroNoiseTest},
    };
    use auto_base_conv::{
        allocate_and_generate_new_glwe_keyswitch_key,
        convert_standard_glwe_keyswitch_key_to_fourier, gen_all_auto_keys,
        generate_scheme_switching_key, glwe_ciphertext_clone_from,
        glwe_ciphertext_monic_monomial_div, keygen_pbs, FourierGlweKeyswitchKey,
    };
    use concrete_fft::c64;
    use tfhe::core_crypto::{fft_impl::common::fast_pbs_modulus_switch, prelude::*};
    #[test]
    fn cbs_trial() {
        let param = *ZeroNoiseTest;
        let lwe_dimension = param.lwe_dimension();
        let lwe_modular_std_dev = param.lwe_modular_std_dev();
        let polynomial_size = param.polynomial_size();
        let glwe_dimension = param.glwe_dimension();
        let glwe_modular_std_dev = param.glwe_modular_std_dev();
        let large_glwe_dimension = param.large_glwe_dimension();
        let large_glwe_modular_std_dev = param.large_glwe_modular_std_dev();
        let pbs_base_log = param.pbs_base_log();
        let pbs_level = param.pbs_level();
        let ks_base_log = param.ks_base_log();
        let ks_level = param.ks_level();
        let glwe_ds_to_large_base_log = param.glwe_ds_to_large_base_log();
        let glwe_ds_to_large_level = param.glwe_ds_to_large_level();
        let fft_type_to_large = param.fft_type_to_large();
        let glwe_ds_from_large_base_log = param.glwe_ds_from_large_base_log();
        let glwe_ds_from_large_level = param.glwe_ds_from_large_level();
        let fft_type_from_large = param.fft_type_from_large();
        let auto_base_log = param.auto_base_log();
        let auto_level = param.auto_level();
        let auto_fft_type = param.fft_type_auto();
        let ss_base_log = param.ss_base_log();
        let ss_level = param.ss_level();
        let cbs_base_log = param.cbs_base_log();
        let cbs_level = param.cbs_level();
        let log_lut_count = param.log_lut_count();
        let ciphertext_modulus = param.ciphertext_modulus();
        let message_size = param.message_size();

        let extract_size = 4;
        let glwe_size = glwe_dimension.to_glwe_size();
        let large_glwe_size = large_glwe_dimension.to_glwe_size();

        // Set random generators and buffers
        let mut boxed_seeder = new_seeder();
        let seeder = boxed_seeder.as_mut();

        let mut secret_generator =
            SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
        let mut encryption_generator =
            EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);

        // Generate keys
        let (lwe_sk, glwe_sk, _, bsk, _) = keygen_pbs(
            lwe_dimension,
            glwe_dimension,
            polynomial_size,
            lwe_modular_std_dev,
            glwe_modular_std_dev,
            pbs_base_log,
            pbs_level,
            ks_base_log,
            ks_level,
            &mut secret_generator,
            &mut encryption_generator,
        );
        let bsk = bsk.as_view();

        let lwe_sk_after_ks = allocate_and_generate_new_reused_lwe_key(&lwe_sk, lwe_dimension);

        // let ksk = allocate_and_generate_new_stored_reused_lwe_keyswitch_key(
        //     &lwe_sk,
        //     &lwe_sk_after_ks,
        //     ks_base_log,
        //     ks_level,
        //     lwe_modular_std_dev,
        //     ciphertext_modulus,
        //     &mut encryption_generator,
        // );

        let large_glwe_sk = allocate_and_generate_new_binary_glwe_secret_key(
            large_glwe_dimension,
            polynomial_size,
            &mut secret_generator,
        );

        let glwe_ksk_to_large = allocate_and_generate_new_glwe_keyswitch_key(
            &glwe_sk,
            &large_glwe_sk,
            glwe_ds_to_large_base_log,
            glwe_ds_to_large_level,
            large_glwe_modular_std_dev,
            ciphertext_modulus,
            &mut encryption_generator,
        );
        let mut fourier_glwe_ksk_to_large = FourierGlweKeyswitchKey::new(
            glwe_size,
            large_glwe_size,
            polynomial_size,
            glwe_ds_to_large_base_log,
            glwe_ds_to_large_level,
            fft_type_to_large,
        );
        convert_standard_glwe_keyswitch_key_to_fourier(
            &glwe_ksk_to_large,
            &mut fourier_glwe_ksk_to_large,
        );

        let glwe_ksk_from_large = allocate_and_generate_new_glwe_keyswitch_key(
            &large_glwe_sk,
            &glwe_sk,
            glwe_ds_from_large_base_log,
            glwe_ds_from_large_level,
            glwe_modular_std_dev,
            ciphertext_modulus,
            &mut encryption_generator,
        );
        let mut fourier_glwe_ksk_from_large = FourierGlweKeyswitchKey::new(
            large_glwe_size,
            glwe_size,
            polynomial_size,
            glwe_ds_from_large_base_log,
            glwe_ds_from_large_level,
            fft_type_from_large,
        );
        convert_standard_glwe_keyswitch_key_to_fourier(
            &glwe_ksk_from_large,
            &mut fourier_glwe_ksk_from_large,
        );

        let auto_keys = gen_all_auto_keys(
            auto_base_log,
            auto_level,
            auto_fft_type,
            &large_glwe_sk,
            large_glwe_modular_std_dev,
            &mut encryption_generator,
        );

        let ss_key_owned = generate_scheme_switching_key(
            &glwe_sk,
            ss_base_log,
            ss_level,
            glwe_modular_std_dev,
            ciphertext_modulus,
            &mut encryption_generator,
        );
        let ss_key = ss_key_owned.as_view();

        // Set input LWE ciphertext
        for msg in 0..16 {
            let lwe = allocate_and_encrypt_new_lwe_ciphertext(
                &lwe_sk,
                Plaintext(msg << (u64::BITS as usize - message_size)),
                glwe_modular_std_dev,
                ciphertext_modulus,
                &mut encryption_generator,
            );

            let log_scale = u64::BITS as usize - message_size;
            let acc_plaintext = PlaintextList::from_container(
                (0..polynomial_size.0)
                    .map(|i| {
                        if i < (1 << extract_size) {
                            if (i >> (extract_size - 1)) == 0 {
                                (i << log_scale) as u64
                            } else {
                                (((1 << (extract_size - 1)) + ((1 << extract_size) - 1 - i))
                                    << log_scale) as u64
                            }
                        } else {
                            u64::ZERO
                        }
                    })
                    .collect::<Vec<u64>>(),
            );
            let acc_id = allocate_and_trivially_encrypt_new_glwe_ciphertext(
                glwe_size,
                &acc_plaintext,
                ciphertext_modulus,
            );

            let mut ct_temp =
                GlweCiphertext::new(u64::ZERO, glwe_size, polynomial_size, ciphertext_modulus);

            let mut glwe_out =
                GlweCiphertext::new(u64::ZERO, glwe_size, polynomial_size, ciphertext_modulus);

            glwe_ciphertext_clone_from(&mut glwe_out, &acc_id);
            let mut fourier_ggsw_list_out = FourierGgswCiphertextList::new(
                vec![
                    c64::default();
                    extract_size
                        * polynomial_size.to_fourier_polynomial_size().0
                        * glwe_size.0
                        * glwe_size.0
                        * cbs_level.0
                ],
                extract_size,
                glwe_size,
                polynomial_size,
                cbs_base_log,
                cbs_level,
            );

            ///////////////////////////////////////////////////////////////////

            let mut acc_glev = GlweCiphertextList::new(
                u64::ZERO,
                glwe_size,
                polynomial_size,
                GlweCiphertextCount(cbs_level.0),
                ciphertext_modulus,
            );

            let mut ggsw_list_out = GgswCiphertextList::new(
                u64::ZERO,
                glwe_size,
                polynomial_size,
                cbs_base_log,
                cbs_level,
                GgswCiphertextCount(message_size),
                ciphertext_modulus,
            );
            ///////////////////////////////////////////////////////////////////
            /// Start the simulation after keyswitching
            let small_lwe = allocate_and_encrypt_new_lwe_ciphertext(
                &lwe_sk_after_ks,
                Plaintext(msg << 60),
                lwe_modular_std_dev,
                ciphertext_modulus,
                &mut encryption_generator,
            );
            // test the modulus switching step
            let (mask, body) = fast_low_noise_pbs_modulus_switch(
                &small_lwe,
                polynomial_size,
                ModulusSwitchOffset(0),
                log_lut_count,
            );
            // print!("our body: {}, mask: [", body.0);
            // for (i, m) in mask.iter().enumerate() {
            //     if i != 0 {
            //         print!(", ");
            //     }
            //     print!("{}", m.0);
            // }
            // println!("]");
            // let (lwe_mask, lwe_body) = small_lwe.get_mask_and_body();
            // print!(
            //     " their body: {}, mask: [",
            //     fast_pbs_modulus_switch(
            //         *lwe_body.data,
            //         polynomial_size,
            //         ModulusSwitchOffset(0),
            //         log_lut_count,
            //     )
            // );
            // for (i, m) in lwe_mask.as_ref().iter().enumerate() {
            //     if i != 0 {
            //         print!(", ");
            //     }
            //     print!(
            //         "{}",
            //         fast_pbs_modulus_switch(
            //             *m,
            //             polynomial_size,
            //             ModulusSwitchOffset(0),
            //             log_lut_count,
            //         )
            //     );
            // }

            /////////////////////////////////////////////////

            for (i, fft_gsw) in fourier_ggsw_list_out.as_view().into_ggsw_iter().enumerate() {
                glwe_ciphertext_monic_monomial_div(&mut ct_temp, &glwe_out, MonomialDegree(1 << i));
                cmux_assign(&mut glwe_out, &mut ct_temp, &fft_gsw);
            }
            let mut lwe_extract = LweCiphertext::new(u64::ZERO, lwe.lwe_size(), ciphertext_modulus);
            extract_lwe_sample_from_glwe_ciphertext(&glwe_out, &mut lwe_extract, MonomialDegree(0));
            let plain2 = decrypt_lwe_ciphertext(&lwe_sk, &lwe_extract);
            println!(
                "Decrypted plaintext: {} -> {:04b}, expected: {}",
                plain2.0 >> 60,
                plain2.0 >> 60,
                msg
            );
        }
    }
}
