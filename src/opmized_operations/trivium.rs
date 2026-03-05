use std::collections::HashMap;

use aligned_vec::ABox;
use rand::seq::index;
use refined_tfhe_lhe::AutomorphKey;
use tfhe::core_crypto::fft_impl::fft64::crypto::bootstrap::FourierLweBootstrapKeyView;
use tfhe::core_crypto::{
    fft_impl::{fft128::crypto::ggsw, fft64::c64},
    prelude::*,
};

use tfhe::core_crypto::fft_impl::fft64::crypto::ggsw::FourierGgswCiphertextListView;

use crate::{
    processors::{
        cbs_4_bits::circuit_bootstrapping_rev_tr_lead_one,
        lwe_stored_ksk::LweStoredReusedKeyswitchKey,
    },
    utils::parms::ProcessorParam,
};

pub const TRIVIUM_STATE_LEN: usize = 288;

pub struct TriviumUnit<Scalar>
where
    Scalar: UnsignedTorus + CastFrom<usize> + CastInto<usize>,
{
    data_type: bool,
    ggsw: FourierGgswCiphertext<ABox<[c64]>>,
    glwe: GlweCiphertextOwned<Scalar>,
}

impl<Scalar> TriviumUnit<Scalar>
where
    Scalar: UnsignedTorus + CastFrom<usize> + CastInto<usize>,
{
    pub fn new(
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        Self {
            data_type: true,
            ggsw: FourierGgswCiphertext::<ABox<[c64]>>::new(
                glwe_size,
                polynomial_size,
                decomposition_base_log,
                decomposition_level_count,
            ),
            glwe: GlweCiphertextOwned::new(
                Scalar::ZERO,
                glwe_size,
                polynomial_size,
                ciphertext_modulus,
            ),
        }
    }

    pub fn set_data_type_ggsw(&mut self) {
        self.data_type = true;
    }

    pub fn set_data_type_glwe(&mut self) {
        self.data_type = false;
    }

    pub fn is_ggsw(&self) -> bool {
        self.data_type
    }

    pub fn ggsw(&self) -> &FourierGgswCiphertext<ABox<[c64]>> {
        &self.ggsw
    }

    pub fn ggsw_mut(&mut self) -> &mut FourierGgswCiphertext<ABox<[c64]>> {
        &mut self.ggsw
    }

    pub fn glwe(&self) -> &GlweCiphertextOwned<Scalar> {
        &self.glwe
    }

    pub fn glwe_mut(&mut self) -> &mut GlweCiphertextOwned<Scalar> {
        &mut self.glwe
    }
}

pub struct TriviumState<Scalar>
where
    Scalar: UnsignedTorus + CastFrom<usize> + CastInto<usize>,
{
    state: [TriviumUnit<Scalar>; TRIVIUM_STATE_LEN],
    glwe_buffer: GlweCiphertextOwned<Scalar>,
    large_lwe_buffer: LweCiphertextOwned<Scalar>,
    ggsw_buffer: GgswCiphertext<Vec<Scalar>>,
    polynomial_size: PolynomialSize,
    glwe_size: GlweSize,
    ciphertext_modulus: CiphertextModulus<Scalar>,
    index: usize,
}

impl<Scalar> TriviumState<Scalar>
where
    Scalar: UnsignedTorus + CastFrom<usize> + CastInto<usize>,
{
    fn encrypt_bit_to_state(
        &mut self,
        index: usize,
        bit: Scalar,
        fourier_bsk: FourierLweBootstrapKeyView<'_>,
        auto_keys: &HashMap<usize, AutomorphKey<ABox<[c64]>>>,
        ss_key: FourierGgswCiphertextListView,
        ksk: &LweStoredReusedKeyswitchKey<Vec<Scalar>>,
        parms: &ProcessorParam<Scalar>,
    ) {
        let fourier_ggsw = self.state[index].ggsw_mut();
        let mut lwe = self.large_lwe_buffer.as_mut_view();
        trivially_encrypt_lwe_ciphertext(&mut lwe, Plaintext(bit << 63));
        circuit_bootstrapping_rev_tr_lead_one(
            &lwe,
            &mut self.ggsw_buffer,
            fourier_bsk,
            auto_keys,
            ss_key,
            ksk,
            parms,
        );
        convert_standard_ggsw_ciphertext_to_fourier(&self.ggsw_buffer, fourier_ggsw);
    }

    pub fn new(
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        let state = std::array::from_fn(|_| {
            TriviumUnit::new(
                glwe_size,
                polynomial_size,
                decomposition_base_log,
                decomposition_level_count,
                ciphertext_modulus,
            )
        });

        let glwe_buffer =
            GlweCiphertextOwned::new(Scalar::ZERO, glwe_size, polynomial_size, ciphertext_modulus);

        let large_lwe_buffer = LweCiphertextOwned::new(
            Scalar::ZERO,
            LweDimension(glwe_size.to_glwe_dimension().0 * polynomial_size.0).to_lwe_size(),
            ciphertext_modulus,
        );

        let ggsw_buffer = GgswCiphertext::new(
            Scalar::ZERO,
            glwe_size,
            polynomial_size,
            decomposition_base_log,
            decomposition_level_count,
            ciphertext_modulus,
        );

        let index = 0;

        Self {
            state,
            glwe_buffer,
            large_lwe_buffer,
            ggsw_buffer,
            polynomial_size,
            glwe_size,
            ciphertext_modulus,
            index,
        }
    }

    pub fn init_state(
        &mut self,
        key: &[Scalar; 80],
        iv: &[Scalar; 80],
        fourier_bsk: FourierLweBootstrapKeyView<'_>,
        auto_keys: &HashMap<usize, AutomorphKey<ABox<[c64]>>>,
        ss_key: FourierGgswCiphertextListView,
        ksk: &LweStoredReusedKeyswitchKey<Vec<Scalar>>,
        parms: &ProcessorParam<Scalar>,
    ) {
        self.encrypt_bit_to_state(0, Scalar::ZERO, fourier_bsk, auto_keys, ss_key, ksk, parms);
        self.encrypt_bit_to_state(1, Scalar::ONE, fourier_bsk, auto_keys, ss_key, ksk, parms);

        let zero_fourier = self.state[0].ggsw().as_view().data().to_vec();
        let one_fourier = self.state[1].ggsw().as_view().data().to_vec();

        for unit in self.state.iter_mut() {
            unit.ggsw_mut()
                .as_mut_view()
                .data()
                .copy_from_slice(&zero_fourier);
        }

        for i in 0..80 {
            let bit_cipher = if key[i] == Scalar::ZERO {
                &zero_fourier
            } else {
                &one_fourier
            };
            self.state[i]
                .ggsw_mut()
                .as_mut_view()
                .data()
                .copy_from_slice(bit_cipher);
        }

        for i in 0..80 {
            let bit_cipher = if iv[i] == Scalar::ZERO {
                &zero_fourier
            } else {
                &one_fourier
            };
            self.state[i + 93]
                .ggsw_mut()
                .as_mut_view()
                .data()
                .copy_from_slice(bit_cipher);
        }

        for i in 0..3 {
            self.state[i + 285]
                .ggsw_mut()
                .as_mut_view()
                .data()
                .copy_from_slice(&one_fourier);
        }
    }

    pub fn get_output_bit(&self) -> GlweCiphertextOwned<Scalar> {
        let zero_list = PlaintextList::new(Scalar::ZERO, PlaintextCount(self.polynomial_size.0));
        let mut output = allocate_and_trivially_encrypt_new_glwe_ciphertext(
            self.glwe_size,
            &zero_list,
            self.ciphertext_modulus,
        );

        output
    }

    pub fn next_state(&mut self) {}

    pub fn len(&self) -> usize {
        TRIVIUM_STATE_LEN
    }

    pub fn unit(&self, index: usize) -> &TriviumUnit<Scalar> {
        &self.state[index]
    }

    pub fn unit_mut(&mut self, index: usize) -> &mut TriviumUnit<Scalar> {
        &mut self.state[index]
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut TriviumUnit<Scalar>> {
        self.state.iter_mut()
    }
}
