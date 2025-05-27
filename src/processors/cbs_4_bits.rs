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

use super::low_noise_ms::fast_low_noise_pbs_modulus_switch;

pub fn circuit_bootstrapping_4_bits_at_once<Scalar, InputCont, OutputCont, FourierCont>(
    input: &LweCiphertext<InputCont>,
    output: &mut GgswCiphertextList<OutputCont>,
    fourier_bsk: FourierLweBootstrapKey<FourierCont>,
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
    let mut small_lwe = LweCiphertext::new(
        Scalar::ZERO,
        ksk.output_lwe_size(),
        ksk.ciphertext_modulus(),
    );

    keyswitch_lwe_ciphertext(&ksk, &input, &mut small_lwe);

    let (mask, body) = fast_low_noise_pbs_modulus_switch(
        &small_lwe,
        parms.polynomial_size(),
        ModulusSwitchOffset(0),
        parms.log_lut_count(),
    );

    


}
