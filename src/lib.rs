#[global_allocator]
static GLOBAL: jemallocator::Jemalloc = jemallocator::Jemalloc;
pub mod operations;
pub mod opmized_operations;
pub mod processors;
pub mod programs;
pub mod utils;

#[cfg(test)]
mod manager_tests {
    use std::time::Instant;

    use jemalloc_ctl::opt::zero;
    use num_traits::ToPrimitive;
    use rand::Rng;
    use refined_tfhe_lhe::{gen_all_auto_keys, generate_scheme_switching_key};
    use tfhe::{
        boolean::prelude::DecompositionLevelCount,
        core_crypto::{
            fft_impl::fft128::crypto::ggsw::add_external_product_assign,
            prelude::{
                allocate_and_encrypt_new_lwe_ciphertext,
                allocate_and_generate_new_binary_glwe_secret_key,
                allocate_and_generate_new_lwe_bootstrap_key,
                allocate_and_trivially_encrypt_new_glwe_ciphertext,
                cmux_assign_mem_optimized_requirement, convert_standard_ggsw_ciphertext_to_fourier,
                convert_standard_lwe_bootstrap_key_to_fourier, decrypt_glwe_ciphertext,
                encrypt_glwe_ciphertext, ActivatedRandomGenerator, CastInto, ComputationBuffers,
                ContiguousEntityContainer, EncryptionRandomGenerator, Fft, FourierGgswCiphertext,
                FourierLweBootstrapKey, GgswCiphertext, GlweCiphertext, Plaintext, PlaintextList,
                SecretRandomGenerator,
            },
            seeders::new_seeder,
        },
        shortint::wopbs::PlaintextCount,
    };

    use crate::{
        operations::{
            cipher_lut::add_external_product_assign_lead_one,
            manager::{OperationManager, Step},
            operand::ArithmeticOp,
            operation::OperandType,
        },
        processors::{
            cbs_4_bits::circuit_bootstrapping_rev_tr_lead_one,
            key_gen::allocate_and_generate_new_reused_lwe_key,
            lwe_stored_ksk::allocate_and_generate_new_stored_reused_lwe_keyswitch_key,
        },
        programs::{
            average::AverageProgram, bubble::BubbleProgram, maximum::MaximumProgram,
            squaresum::SquaresumProgram,
        },
        utils::{
            instance::{SetI, SetII, SetTest},
            parms,
        },
    };
    const SAMPLE_SIZE: usize = 10;

    #[test]
    fn test_lead_one_cbs() {
        let param = &SetTest;
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
        let extract_size = param.extract_size();
        let glwe_size = glwe_dimension.to_glwe_size();

        let mut boxed_seeder = new_seeder();
        let seeder = boxed_seeder.as_mut();

        let mut secret_generator =
            SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
        let mut encryption_generator =
            EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);

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
        let fourier_bsk = fourier_bsk.as_view();

        let mut input = allocate_and_encrypt_new_lwe_ciphertext(
            &glwe_lwe_sk,
            Plaintext(1_u64 << (63)),
            glwe_modular_std_dev,
            ciphertext_modulus,
            &mut encryption_generator,
        );
        let plain_list = PlaintextList::new(1 << 63, PlaintextCount(polynomial_size.0));
        let mut zero_list = PlaintextList::new(0, PlaintextCount(polynomial_size.0));
        let mut glwe = GlweCiphertext::new(0, glwe_size, polynomial_size, ciphertext_modulus);
        encrypt_glwe_ciphertext(
            &glwe_sk,
            &mut glwe,
            &plain_list,
            glwe_modular_std_dev,
            &mut encryption_generator,
        );

        let mut out = allocate_and_trivially_encrypt_new_glwe_ciphertext(
            glwe_size,
            &zero_list,
            ciphertext_modulus,
        );

        let glwe_view = glwe.as_view();

        let mut ggsw = GgswCiphertext::new(
            0_u64,
            glwe_size,
            polynomial_size,
            cbs_base_log,
            cbs_level,
            ciphertext_modulus,
        );

        let mut fourier_ggsw =
            FourierGgswCiphertext::new(glwe_size, polynomial_size, cbs_base_log, cbs_level);
        circuit_bootstrapping_rev_tr_lead_one(
            &input,
            &mut ggsw,
            fourier_bsk,
            &auto_keys,
            ss_key,
            &ksk,
            param,
        );

        // let glist = ggsw.as_glwe_list();
        // for glwe_temp in glist.iter() {
        //     let mut zero_list = PlaintextList::new(0, PlaintextCount(polynomial_size.0));
        //     decrypt_glwe_ciphertext(&glwe_sk, &glwe_temp, &mut zero_list);
        //     let binding = zero_list.as_view();
        //     let result = binding.get(0).0;
        //     println!("ggsw result = {:064b}", result);
        // }

        convert_standard_ggsw_ciphertext_to_fourier(&ggsw, &mut fourier_ggsw);
        let fourier_ggsw = fourier_ggsw.as_view();

        let fft = Fft::new(polynomial_size);
        let fft_viwe = fft.as_view();
        let mut buffer = ComputationBuffers::new();
        let buffer_size_req =
            cmux_assign_mem_optimized_requirement::<u64>(glwe_size, polynomial_size, fft_viwe)
                .unwrap()
                .unaligned_bytes_required();

        buffer.resize(buffer_size_req);
        let stuck = buffer.stack();

        add_external_product_assign_lead_one(
            out.as_mut_view(),
            fourier_ggsw,
            glwe_view,
            fft_viwe,
            stuck,
        );

        decrypt_glwe_ciphertext(&glwe_sk, &out, &mut zero_list);
        let binding = zero_list.as_view();
        let result = binding.get(0).0;
        println!("result = {:064b}", result);
        println!("decoded = {}", (((result >> 62) + 1) >> 1) & 1);
    }
}
