use aligned_vec::{ABox, ConstAlign};
use refined_tfhe_lhe::{AutomorphKey, FourierGlweKeyswitchKey};
use std::{collections::HashMap, time::Instant};
use tfhe::core_crypto::{
    fft_impl::fft64::{c64, crypto::bootstrap::FourierLweBootstrapKeyView},
    prelude::*,
};

use crate::{
    processors::{
        convert::convert_to_ggsw_after_blind_rotate_4_bit_rev_tr,
        lwe_stored_ksk::LweStoredReusedKeyswitchKey,
        lwe_storede_ks::stored_reused_keyswitch_lwe_ciphertext,
    },
    utils::parms::ProcessorParam,
};

use super::{
    convert::convert_to_ggsw_after_blind_rotate_4_bit,
    low_noise_ms::fast_low_noise_pbs_modulus_switch, pbs::pbs_many_lut_after_ms_before_extract,
};

use tfhe::core_crypto::fft_impl::fft64::crypto::ggsw::FourierGgswCiphertextListView;

pub fn circuit_bootstrapping_4_bits_at_once<Scalar, InputCont>(
    input: &LweCiphertext<InputCont>,
    output: &mut FourierGgswCiphertextList<Vec<c64>>,
    fourier_bsk: FourierLweBootstrapKeyView<'_>,
    auto_keys: &HashMap<usize, AutomorphKey<ABox<[c64]>>>,
    ss_key: FourierGgswCiphertextListView,
    ksk: &LweStoredReusedKeyswitchKey<Vec<Scalar>>,
    fourier_glwe_ksk_to_large: &FourierGlweKeyswitchKey<ABox<[c64], ConstAlign<128>>>,
    fourier_glwe_ksk_from_large: &FourierGlweKeyswitchKey<ABox<[c64], ConstAlign<128>>>,
    parms: &ProcessorParam<Scalar>,
) where
    Scalar: UnsignedTorus + CastInto<usize> + CastFrom<usize>,
    InputCont: Container<Element = Scalar>,
{
    let polynomial_size = parms.polynomial_size();
    let cbs_base_log = parms.cbs_base_log();
    let cbs_level = parms.cbs_level();
    let glwe_size = parms.glwe_dimension().to_glwe_size();
    let ciphertext_modulus = parms.ciphertext_modulus();
    let log_lut_count = parms.log_lut_count();
    let message_size = parms.message_size();

    ///////////////////////////////////////////////////////////////////
    let mut small_lwe = LweCiphertext::new(Scalar::ZERO, ksk.output_lwe_size(), ciphertext_modulus);

    let mut acc_glev = GlweCiphertextList::new(
        Scalar::ZERO,
        glwe_size,
        polynomial_size,
        GlweCiphertextCount(cbs_level.0),
        ciphertext_modulus,
    );

    // let mut ggsw_list_out = GgswCiphertextList::new(
    //     Scalar::ZERO,
    //     glwe_size,
    //     polynomial_size,
    //     cbs_base_log,
    //     cbs_level,
    //     GgswCiphertextCount(message_size),
    //     ciphertext_modulus,
    // );
    // use std::time::Instant;

    // let ks_start = Instant::now();

    ///////////////////////////////////////////////////////////////////
    stored_reused_keyswitch_lwe_ciphertext(&ksk, &input, &mut small_lwe);

    // println!("stored reused keyswitch time: {:.3?}", ks_start.elapsed());

    // let ms_start = Instant::now();
    let (mask, body) = fast_low_noise_pbs_modulus_switch(
        &small_lwe,
        parms.polynomial_size(),
        ModulusSwitchOffset(0),
        parms.log_lut_count(),
    );
    // println!("modulus keyswitch time: {:.3?}", ms_start.elapsed());
    // let pbs_start = Instant::now();
    pbs_many_lut_after_ms_before_extract(
        &body,
        &mask,
        &mut acc_glev,
        fourier_bsk,
        log_lut_count,
        cbs_base_log,
        cbs_level,
        4,
        ciphertext_modulus,
    );
    // println!("pbs time: {:.3?}", pbs_start.elapsed());
    // let ss_start = Instant::now();

    let mut ggsw_temp = GgswCiphertext::new(
        Scalar::ZERO,
        glwe_size,
        polynomial_size,
        cbs_base_log,
        cbs_level,
        ciphertext_modulus,
    );
    for (i, mut fourier_ggsw) in output.as_mut_view().into_ggsw_iter().enumerate() {
        convert_to_ggsw_after_blind_rotate_4_bit(
            &acc_glev,
            &mut ggsw_temp,
            i,
            &fourier_glwe_ksk_to_large,
            &fourier_glwe_ksk_from_large,
            &auto_keys,
            ss_key,
            ciphertext_modulus,
        );
        convert_standard_ggsw_ciphertext_to_fourier(&ggsw_temp, &mut fourier_ggsw);
    }
    // println!("ss time: {:.3?}", ss_start.elapsed());
}

pub fn circuit_bootstrapping_4_bits_at_once_rev_tr<Scalar, InputCont>(
    input: &LweCiphertext<InputCont>,
    output: &mut FourierGgswCiphertextList<Vec<c64>>,
    fourier_bsk: FourierLweBootstrapKeyView<'_>,
    auto_keys: &HashMap<usize, AutomorphKey<ABox<[c64]>>>,
    ss_key: FourierGgswCiphertextListView,
    ksk: &LweStoredReusedKeyswitchKey<Vec<Scalar>>,
    parms: &ProcessorParam<Scalar>,
) where
    Scalar: UnsignedTorus + CastInto<usize> + CastFrom<usize>,
    InputCont: Container<Element = Scalar>,
{
    let polynomial_size = parms.polynomial_size();
    let cbs_base_log = parms.cbs_base_log();
    let cbs_level = parms.cbs_level();
    let glwe_size = parms.glwe_dimension().to_glwe_size();
    let ciphertext_modulus = parms.ciphertext_modulus();
    let log_lut_count = parms.log_lut_count();
    let num_extracts = parms.extract_size();
    ///////////////////////////////////////////////////////////////////
    let mut small_lwe = LweCiphertext::new(Scalar::ZERO, ksk.output_lwe_size(), ciphertext_modulus);

    let mut acc_glev = GlweCiphertextList::new(
        Scalar::ZERO,
        glwe_size,
        polynomial_size,
        GlweCiphertextCount(cbs_level.0),
        ciphertext_modulus,
    );

    ///////////////////////////////////////////////////////////////////
    stored_reused_keyswitch_lwe_ciphertext(&ksk, &input, &mut small_lwe);
    // let pbs_start = Instant::now();
    let (mask, body) = fast_low_noise_pbs_modulus_switch(
        &small_lwe,
        parms.polynomial_size(),
        ModulusSwitchOffset(0),
        parms.log_lut_count(),
    );
    
    pbs_many_lut_after_ms_before_extract(
        &body,
        &mask,
        &mut acc_glev,
        fourier_bsk,
        log_lut_count,
        cbs_base_log,
        cbs_level,
        num_extracts,
        ciphertext_modulus,
    );
    // println!("pbs time: {:.3?}", pbs_start.elapsed());
    

    let mut ggsw_temp = GgswCiphertext::new(
        Scalar::ZERO,
        glwe_size,
        polynomial_size,
        cbs_base_log,
        cbs_level,
        ciphertext_modulus,
    );
    // let ss_start = Instant::now();
    for (i, mut fourier_ggsw) in output.as_mut_view().into_ggsw_iter().enumerate() {
        convert_to_ggsw_after_blind_rotate_4_bit_rev_tr(
            &acc_glev,
            &mut ggsw_temp,
            i,
            &auto_keys,
            ss_key,
            ciphertext_modulus,
        );
        convert_standard_ggsw_ciphertext_to_fourier(&ggsw_temp, &mut fourier_ggsw);
    }
    // println!("ss time: {:.3?}", ss_start.elapsed());
}
