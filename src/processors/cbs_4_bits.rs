use aligned_vec::ABox;
use auto_base_conv::AutomorphKey;
use std::collections::HashMap;
use tfhe::{
    core_crypto::{
        fft_impl::fft64::{
            c64,
            crypto::{
                bootstrap::FourierLweBootstrapKeyView,
                ggsw::{FourierGgswCiphertextListMutView, FourierGgswCiphertextListView},
            },
        },
        prelude::{CiphertextModulus, *},
    },
    shortint::prelude::*,
};

use crate::utils::parms::ProcessorParam;

use super::{
    low_noise_ms::fast_low_noise_pbs_modulus_switch, pbs::pbs_many_lut_after_ms_before_extract,
};

pub fn circuit_bootstrapping_4_bits_at_once<Scalar, InputCont, OutputCont, FourierCont>(
    input: &LweCiphertext<InputCont>,
    output: &mut GgswCiphertextList<OutputCont>,
    fourier_bsk: FourierLweBootstrapKeyView<'_>,
    auto_keys: &HashMap<usize, AutomorphKey<ABox<[c64]>>>,
    ss_key: FourierGgswCiphertextList<FourierCont>,
    ksk: LweKeyswitchKey<Vec<Scalar>>,
    parms: &ProcessorParam<Scalar>,
) where
    Scalar: UnsignedTorus + CastInto<usize> + CastFrom<usize>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    FourierCont: Container<Element = c64>,
{
    let polynomial_size = parms.polynomial_size();
    let cbs_base_log = parms.cbs_base_log();
    let cbs_level = parms.cbs_level();
    let ksk_base_log = parms.ks_base_log();
    let ksk_level = parms.ks_level();
    let glwe_size = parms.glwe_dimension().to_glwe_size();
    let ciphertext_modulus  = parms.ciphertext_modulus();
    let log_lut_count = parms.log_lut_count();
    let extract_size = parms.extract_size();

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
    keyswitch_lwe_ciphertext(&ksk, &input, &mut small_lwe);

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
        4,
        ciphertext_modulus,
    );

    


}
