use chrono::SubsecRound;

#[global_allocator]
static GLOBAL: jemallocator::Jemalloc = jemallocator::Jemalloc;
pub mod operations;
pub mod opmized_operations;
pub mod processors;
pub mod programs;
pub mod utils;

pub fn run_trivium_demo() {
    use std::time::{Duration, Instant};

    use rand::Rng;
    use refined_tfhe_lhe::{gen_all_auto_keys, generate_scheme_switching_key};
    use tfhe::core_crypto::{
        prelude::{
            allocate_and_generate_new_binary_glwe_secret_key, allocate_and_generate_new_lwe_bootstrap_key,
            convert_standard_lwe_bootstrap_key_to_fourier, decrypt_lwe_ciphertext, ActivatedRandomGenerator,
            EncryptionRandomGenerator, FourierLweBootstrapKey, SecretRandomGenerator,
        },
        seeders::new_seeder,
    };

    use crate::{
        opmized_operations::trivium::TriviumState,
        processors::{
            key_gen::allocate_and_generate_new_reused_lwe_key,
            lwe_stored_ksk::allocate_and_generate_new_stored_reused_lwe_keyswitch_key,
        },
        utils::{instance::TriviumSet, plain_trivium::PlainTrivium},
    };

    let param = &TriviumSet;
    let lwe_dimension = param.lwe_dimension();
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
    let glwe_size = glwe_dimension.to_glwe_size();

    let mut boxed_seeder = new_seeder();
    let seeder = boxed_seeder.as_mut();
    let mut secret_generator = SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
    let mut encryption_generator =
        EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);

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

    let mut rng = rand::thread_rng();
    let key = (0..80)
        .map(|_| u64::from(rng.gen_bool(0.5)))
        .collect::<Vec<u64>>();
    let iv = (0..80)
        .map(|_| u64::from(rng.gen_bool(0.5)))
        .collect::<Vec<u64>>();

    println!(
        "key = {}",
        key.iter()
            .map(|b| if *b == 0 { '0' } else { '1' })
            .collect::<String>()
    );
    println!(
        "iv  = {}",
        iv.iter()
            .map(|b| if *b == 0 { '0' } else { '1' })
            .collect::<String>()
    );

    let mut plain_trivium = PlainTrivium::new(key.clone(), iv.clone());
    let mut trivium = TriviumState::new(
        glwe_size,
        polynomial_size,
        cbs_base_log,
        cbs_level,
        ciphertext_modulus,
    );
    trivium.init_state(&key, &iv, fourier_bsk, &auto_keys, ss_key, &ksk, param);

    let chunk_bits = 64usize;
    let rounds = 20usize;
    let mut total_duration = Duration::ZERO;
    for round in 0..rounds {
        let start = Instant::now();
        let result_chunk = trivium.run(chunk_bits, fourier_bsk, &auto_keys, ss_key, &ksk, param);
        let elapsed = start.elapsed();
        total_duration += elapsed;

        let mut result_bits = String::with_capacity(chunk_bits);
        for lwe in &result_chunk {
            let decrypted = decrypt_lwe_ciphertext(&glwe_lwe_sk, lwe);
            let bit = (((decrypted.0 >> 62) + 1) >> 1) & 1;
            result_bits.push(if bit == 0 { '0' } else { '1' });
        }

        let expected = plain_trivium.gen_u64();
        println!("Round {round}:\n{:064b}\n{}\ntime: {:?}\n", expected, result_bits, elapsed);
    }

    println!(
        "total time for {} bits: {:?}, average per 64 bits: {:?}",
        rounds * chunk_bits,
        total_duration,
        total_duration / rounds as u32
    );
}

#[cfg(test)]
mod manager_tests {
    #[test]
    fn test_lead_one_cbs() {
        crate::run_trivium_demo();
    }
}
