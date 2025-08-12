#[global_allocator]
static GLOBAL: jemallocator::Jemalloc = jemallocator::Jemalloc;
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
    use std::time::Instant;

    use crate::{
        operations::{
            manager::{concat_ggsw_lists, OperationManager, Step},
            operand::ArithmeticOp,
            operation::{OperandType::*, Operation},
        },
        processors::{
            cbs_4_bits::circuit_bootstrapping_4_bits_at_once_rev_tr,
            key_gen::allocate_and_generate_new_reused_lwe_key,
            lwe_stored_ksk::allocate_and_generate_new_stored_reused_lwe_keyswitch_key,
        },
        utils::instance::SetI,
    };
    use concrete_fft::c64;
    use rayon::vec;
    use refined_tfhe_lhe::{gen_all_auto_keys, generate_scheme_switching_key};
    use tfhe::core_crypto::prelude::*;
    #[test]
    fn lut_trial() {
        println!("=== Table Look Up Trial Start ===");
        let param = *SetI;
        let lwe_dimension = param.lwe_dimension();
        let lwe_modular_std_dev = param.lwe_modular_std_dev();
        let polynomial_size = param.polynomial_size();
        let glwe_dimension = param.glwe_dimension();
        let glwe_modular_std_dev = param.glwe_modular_std_dev();
        let pbs_base_log = param.pbs_base_log();
        let pbs_level = param.pbs_level();
        let ks_base_log = param.ks_base_log();
        let ks_level = param.ks_level();
        let auto_base_log = param.auto_base_log();
        let auto_level = param.auto_level();
        let auto_fft_type = param.fft_type_auto();
        let ss_base_log = param.ss_base_log();
        let ss_level = param.ss_level();
        let cbs_base_log = param.cbs_base_log();
        let cbs_level = param.cbs_level();
        let ciphertext_modulus = param.ciphertext_modulus();
        let message_size = param.message_size();
        let extract_size = 4;
        let glwe_size = glwe_dimension.to_glwe_size();
        let delta = 1 << (u64::BITS as usize - message_size);
        // Set random generators and buffers
        let mut boxed_seeder: Box<dyn Seeder> = new_seeder();
        let seeder: &mut dyn Seeder = boxed_seeder.as_mut();

        let mut secret_generator =
            SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
        let mut encryption_generator =
            EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);

        let keygen_start = Instant::now();
        // Generate keys
        let glwe_sk = allocate_and_generate_new_binary_glwe_secret_key(
            glwe_dimension,
            polynomial_size,
            &mut secret_generator,
        );
        let glwe_lwe_sk = glwe_sk.as_lwe_secret_key();
        let lwe_sk_after_ks = allocate_and_generate_new_reused_lwe_key(&glwe_lwe_sk, lwe_dimension);
        let ksk = allocate_and_generate_new_stored_reused_lwe_keyswitch_key(
            &glwe_lwe_sk,
            &lwe_sk_after_ks,
            ks_base_log,
            ks_level,
            glwe_modular_std_dev,
            ciphertext_modulus,
            &mut encryption_generator,
        );

        let bsk = allocate_and_generate_new_lwe_bootstrap_key(
            &lwe_sk_after_ks,
            &glwe_sk,
            pbs_base_log,
            pbs_level,
            glwe_modular_std_dev,
            ciphertext_modulus,
            &mut encryption_generator,
        );

        let mut fourier_bsk = FourierLweBootstrapKey::new(
            bsk.input_lwe_dimension(),
            bsk.glwe_size(),
            bsk.polynomial_size(),
            bsk.decomposition_base_log(),
            bsk.decomposition_level_count(),
        );
        convert_standard_lwe_bootstrap_key_to_fourier(&bsk, &mut fourier_bsk);
        drop(bsk);
        let fourier_bsk = fourier_bsk.as_view();

        let auto_keys = gen_all_auto_keys(
            auto_base_log,
            auto_level,
            auto_fft_type,
            &glwe_sk,
            glwe_modular_std_dev,
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

        let output_lwe = LweCiphertext::new(
            u64::ZERO,
            glwe_lwe_sk.lwe_dimension().to_lwe_size(),
            ciphertext_modulus,
        );

        let fft = Fft::new(polynomial_size);
        let mut buffer = ComputationBuffers::new();
        let mut lwe_outs = vec![output_lwe; 8];
        println!(
            "Key generation done. Time: {:.3?}, start lut generation",
            keygen_start.elapsed()
        );
        let gen_lut_start = Instant::now();
        let add_op = Operation::new(
            ArithmeticOp::Add,
            crate::operations::operation::OperandType::CipherPlain,
            8,
            4,
            polynomial_size,
            delta,
            Some(0),
        );
        println!("LUT generation time: {:.3?}", gen_lut_start.elapsed());

        // Set input LWE ciphertext
        let mut cbs_times = Vec::new();
        let mut lut_times = Vec::new();

        for msg in 0..=0 {
            let mut fourier_gsw_list_high = FourierGgswCiphertextList::new(
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

            let mut fourier_gsw_list_low = FourierGgswCiphertextList::new(
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

            let mut fourier_gsw_list_zero_high = FourierGgswCiphertextList::new(
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

            let mut fourier_gsw_list_zero_low = FourierGgswCiphertextList::new(
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
            println!("--- msg {} ---", msg);
            let encrypt_start = Instant::now();
            ///////////////////////////////////////////////////////////////////
            // Start the simulation before keyswitching
            let msg_high = msg >> 4;
            let msg_low = msg & 0b00001111;
            println!(
                "Input plaintext: {} -> {:08b}",
                msg_high << 4 | msg_low,
                msg_high << 4 | msg_low,
            );
            let lwe_low = allocate_and_encrypt_new_lwe_ciphertext(
                &glwe_lwe_sk,
                Plaintext(msg_low << (u64::BITS as usize - message_size)),
                lwe_modular_std_dev,
                ciphertext_modulus,
                &mut encryption_generator,
            );
            let lwe_high = allocate_and_encrypt_new_lwe_ciphertext(
                &glwe_lwe_sk,
                Plaintext(msg_high << (u64::BITS as usize - message_size)),
                lwe_modular_std_dev,
                ciphertext_modulus,
                &mut encryption_generator,
            );
            let lwe_zero_low = allocate_and_encrypt_new_lwe_ciphertext(
                &glwe_lwe_sk,
                Plaintext(0u64),
                lwe_modular_std_dev,
                ciphertext_modulus,
                &mut encryption_generator,
            );

            let lwe_zero_high = allocate_and_encrypt_new_lwe_ciphertext(
                &glwe_lwe_sk,
                Plaintext(0u64),
                lwe_modular_std_dev,
                ciphertext_modulus,
                &mut encryption_generator,
            );

            println!("LWE encryption time: {:.3?}", encrypt_start.elapsed());

            let cbs_start = Instant::now();

            circuit_bootstrapping_4_bits_at_once_rev_tr(
                &lwe_low,
                &mut fourier_gsw_list_low,
                fourier_bsk,
                &auto_keys,
                ss_key,
                &ksk,
                &param,
            );

            circuit_bootstrapping_4_bits_at_once_rev_tr(
                &lwe_high,
                &mut fourier_gsw_list_high,
                fourier_bsk,
                &auto_keys,
                ss_key,
                &ksk,
                &param,
            );

            circuit_bootstrapping_4_bits_at_once_rev_tr(
                &lwe_low,
                &mut fourier_gsw_list_zero_low,
                fourier_bsk,
                &auto_keys,
                ss_key,
                &ksk,
                &param,
            );

            circuit_bootstrapping_4_bits_at_once_rev_tr(
                &lwe_high,
                &mut fourier_gsw_list_zero_high,
                fourier_bsk,
                &auto_keys,
                ss_key,
                &ksk,
                &param,
            );

            println!("LWE cbs time: {:.3?}", cbs_start.elapsed());
            cbs_times.push(cbs_start.elapsed());
            let cal_time = Instant::now();

            let ggsw_lists = vec![
                fourier_gsw_list_high.clone(),
                fourier_gsw_list_low.clone(),
                fourier_gsw_list_zero_high.clone(),
                fourier_gsw_list_zero_low.clone(),
                fourier_gsw_list_high,
                fourier_gsw_list_low,
                fourier_gsw_list_zero_high,
                fourier_gsw_list_zero_low,
            ];
            let ggsw_list = concat_ggsw_lists(ggsw_lists, true);

            add_op.vertical_packing_multi_lookup(&mut lwe_outs, &ggsw_list, &fft, &mut buffer);

            let lut_elapsed = cal_time.elapsed();
            println!("LUT calculation time: {:.3?}", lut_elapsed);
            lut_times.push(lut_elapsed);

            let h = decrypt_lwe_ciphertext(&glwe_lwe_sk, &lwe_outs[1]);
            let l = decrypt_lwe_ciphertext(&glwe_lwe_sk, &lwe_outs[0]);
            let result_high = (((h.0 >> 59) + 1) >> 1) % 16;
            let result_low = (((l.0 >> 59) + 1) >> 1) % 16;
            println!(
                "Decrypted plaintext: {} -> {:08b}, expected: {}",
                result_high << 4 | result_low,
                result_high << 4 | result_low,
                (msg * 2) % 256
            );
            // 统计平均时间
        }
        let total_cbs_time = cbs_times.iter().map(|d| d.as_secs_f64()).sum::<f64>();
        let avg_cbs_time = total_cbs_time / cbs_times.len() as f64;
        println!("Average LWE cbs time: {:.6} s", avg_cbs_time);

        let total_lut_time = lut_times.iter().map(|d| d.as_secs_f64()).sum::<f64>();
        let avg_lut_time = total_lut_time / lut_times.len() as f64;
        println!("Average LUT calculation time: {:.6} s", avg_lut_time);
    }

    #[test]
    fn manager_trial() {
        let mut manager = OperationManager::new(*SetI, 10, 8);
        manager.add_operation(ArithmeticOp::Add, PlainCipher, Some(2));
        manager.add_operation(ArithmeticOp::Mul, BothCipher, None);
        manager.set_execution_plan(vec![Step::new(0, vec![0], 0), Step::new(1, vec![0, 1], 2)]);

        for i in 0..100 {
            manager.load_data(i, 0);
            manager.load_data(i + 3, 1);
            manager.execute();
            let result = manager.get_data(2);

            println!("({}+2)*{}={}", i, i + 3, result);
        }
    }
}
