use core::num;
use std::collections::HashMap;

use aligned_vec::ABox;
use pulp::Scalar;
use rand::seq::index;
use refined_tfhe_lhe::AutomorphKey;
use tfhe::core_crypto::fft_impl::fft64::crypto::bootstrap::FourierLweBootstrapKeyView;
use tfhe::core_crypto::{
    fft_impl::{fft128::crypto::ggsw, fft64::c64},
    prelude::*,
};

use tfhe::core_crypto::fft_impl::fft64::crypto::ggsw::FourierGgswCiphertextListView;

use crate::operations::cipher_lut::add_external_product_assign_lead_one;
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
    ggsw: GgswCiphertextOwned<Scalar>,
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
            ggsw: GgswCiphertext::new(
                Scalar::ZERO,
                glwe_size,
                polynomial_size,
                decomposition_base_log,
                decomposition_level_count,
                ciphertext_modulus,
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

    pub fn ggsw(&self) -> &GgswCiphertextOwned<Scalar> {
        &self.ggsw
    }

    pub fn ggsw_view(&self) -> GgswCiphertextView<'_, Scalar> {
        self.ggsw.as_view()
    }

    pub fn ggsw_mut(&mut self) -> &mut GgswCiphertextOwned<Scalar> {
        &mut self.ggsw
    }

    pub fn ggsw_mut_view(&mut self) -> GgswCiphertextMutView<'_, Scalar> {
        self.ggsw.as_mut_view()
    }

    pub fn glwe(&self) -> &GlweCiphertextOwned<Scalar> {
        &self.glwe
    }

    pub fn glwe_view(&self) -> GlweCiphertextView<'_, Scalar> {
        self.glwe.as_view()
    }

    pub fn glwe_mut(&mut self) -> &mut GlweCiphertextOwned<Scalar> {
        &mut self.glwe
    }

    pub fn glwe_mut_view(&mut self) -> GlweCiphertextMutView<'_, Scalar> {
        self.glwe.as_mut_view()
    }

    pub fn extract_glwe_from_ggsw(&mut self) {
        let ggsw = &self.ggsw;
        let glwe = &mut self.glwe;
        let index = glwe.glwe_size().to_glwe_dimension().0;

        glwe.as_mut()
            .copy_from_slice(ggsw.as_glwe_list().get(index).as_ref());
    }

    pub fn cbs_glwe_to_ggsw(
        &mut self,
        fourier_bsk: FourierLweBootstrapKeyView<'_>,
        auto_keys: &HashMap<usize, AutomorphKey<ABox<[c64]>>>,
        ss_key: FourierGgswCiphertextListView,
        ksk: &LweStoredReusedKeyswitchKey<Vec<Scalar>>,
        parms: &ProcessorParam<Scalar>,
    ) {
        let ggsw = &mut self.ggsw;
        let glwe = &self.glwe;
        let mut large_lwe = LweCiphertextOwned::new(
            Scalar::ZERO,
            LweDimension(glwe.glwe_size().to_glwe_dimension().0 * glwe.polynomial_size().0)
                .to_lwe_size(),
            glwe.ciphertext_modulus(),
        );
        extract_lwe_sample_from_glwe_ciphertext(glwe, &mut large_lwe, MonomialDegree(0));
        circuit_bootstrapping_rev_tr_lead_one(
            &large_lwe,
            ggsw,
            fourier_bsk,
            auto_keys,
            ss_key,
            ksk,
            parms,
        );
        self.set_data_type_ggsw();
    }
}

pub struct TriviumState<Scalar>
where
    Scalar: UnsignedTorus + CastFrom<usize> + CastInto<usize>,
{
    state: [TriviumUnit<Scalar>; TRIVIUM_STATE_LEN],
    glwe_buffer: GlweCiphertextOwned<Scalar>,
    large_lwe_buffer: LweCiphertextOwned<Scalar>,
    fourier_ggsw_buffer: FourierGgswCiphertext<ABox<[c64]>>,
    polynomial_size: PolynomialSize,
    glwe_size: GlweSize,
    fft: Fft,
    buffer: ComputationBuffers,
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
        let mut lwe = self.large_lwe_buffer.as_mut_view();
        trivially_encrypt_lwe_ciphertext(&mut lwe, Plaintext(bit << 63));
        circuit_bootstrapping_rev_tr_lead_one(
            &lwe,
            self.state[index].ggsw_mut(),
            fourier_bsk,
            auto_keys,
            ss_key,
            ksk,
            parms,
        );
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
        let fft = Fft::new(polynomial_size);
        let fft_viwe = fft.as_view();
        let mut buffer = ComputationBuffers::new();
        let buffer_size_req =
            cmux_assign_mem_optimized_requirement::<u64>(glwe_size, polynomial_size, fft_viwe)
                .unwrap()
                .unaligned_bytes_required();

        buffer.resize(buffer_size_req);

        let fourier_ggsw_buffer = FourierGgswCiphertext::new(
            glwe_size,
            polynomial_size,
            decomposition_base_log,
            decomposition_level_count,
        );

        let index = 0;

        Self {
            state,
            glwe_buffer,
            large_lwe_buffer,
            fourier_ggsw_buffer,
            polynomial_size,
            glwe_size,
            fft: Fft::new(polynomial_size),
            buffer,
            ciphertext_modulus,
            index,
        }
    }

    pub fn init_state(
        &mut self,
        key: &Vec<Scalar>,
        iv: &Vec<Scalar>,
        fourier_bsk: FourierLweBootstrapKeyView<'_>,
        auto_keys: &HashMap<usize, AutomorphKey<ABox<[c64]>>>,
        ss_key: FourierGgswCiphertextListView,
        ksk: &LweStoredReusedKeyswitchKey<Vec<Scalar>>,
        parms: &ProcessorParam<Scalar>,
    ) {
        self.encrypt_bit_to_state(0, Scalar::ZERO, fourier_bsk, auto_keys, ss_key, ksk, parms);
        self.encrypt_bit_to_state(1, Scalar::ONE, fourier_bsk, auto_keys, ss_key, ksk, parms);

        let zero_ggsw = self.state[0].ggsw().as_ref().to_vec();
        let one_ggsw = self.state[1].ggsw().as_ref().to_vec();

        for unit in self.state.iter_mut() {
            unit.ggsw_mut().as_mut().copy_from_slice(&zero_ggsw);
        }

        for i in 0..80 {
            let bit_cipher = if key[i] == Scalar::ZERO {
                &zero_ggsw
            } else {
                &one_ggsw
            };
            self.state[i]
                .ggsw_mut()
                .as_mut()
                .copy_from_slice(bit_cipher);
        }

        for i in 0..80 {
            let bit_cipher = if iv[i] == Scalar::ZERO {
                &zero_ggsw
            } else {
                &one_ggsw
            };
            self.state[i + 93]
                .ggsw_mut()
                .as_mut()
                .copy_from_slice(bit_cipher);
        }

        for i in 0..3 {
            self.state[i + 285]
                .ggsw_mut()
                .as_mut()
                .copy_from_slice(&one_ggsw);
        }

        for i in 0..288 {
            self.state[i].extract_glwe_from_ggsw();
            self.state[i].set_data_type_ggsw();
        }
    }

    pub fn get_output_bit(&self) -> GlweCiphertextOwned<Scalar> {
        let zero_list = PlaintextList::new(Scalar::ZERO, PlaintextCount(self.polynomial_size.0));
        let mut output = allocate_and_trivially_encrypt_new_glwe_ciphertext(
            self.glwe_size,
            &zero_list,
            self.ciphertext_modulus,
        );
        let i_a = self.index % 93;
        let i_b = self.index % 84;
        let i_c = self.index % 111;
        // s66
        glwe_ciphertext_add_assign(&mut output, &self.state[(93 + 65 - i_a) % 93].glwe());
        // s93
        glwe_ciphertext_add_assign(&mut output, &self.state[(93 + 92 - i_a) % 93].glwe());
        // s162
        glwe_ciphertext_add_assign(&mut output, &self.state[93 + (84 + 68 - i_b) % 84].glwe());
        // s177
        glwe_ciphertext_add_assign(&mut output, &self.state[93 + (84 + 83 - i_b) % 84].glwe());
        // s243
        glwe_ciphertext_add_assign(
            &mut output,
            &self.state[177 + (111 + 65 - i_c) % 111].glwe(),
        );
        // s288
        glwe_ciphertext_add_assign(
            &mut output,
            &self.state[177 + (111 + 110 - i_c) % 111].glwe(),
        );

        output
    }

    pub fn next_state(
        &mut self,
        refresh: bool,
        fourier_bsk: FourierLweBootstrapKeyView<'_>,
        auto_keys: &HashMap<usize, AutomorphKey<ABox<[c64]>>>,
        ss_key: FourierGgswCiphertextListView,
        ksk: &LweStoredReusedKeyswitchKey<Vec<Scalar>>,
        parms: &ProcessorParam<Scalar>,
    ) {
        let fft_view = self.fft.as_view();
        let i_a = self.index % 93;
        let i_b = self.index % 84;
        let i_c = self.index % 111;

        // --- register A ---
        let s66 = &self.state[(93 + 65 - i_a) % 93];
        let s69 = &self.state[(93 + 68 - i_a) % 93];
        let s91 = &self.state[(93 + 90 - i_a) % 93];
        let s92 = &self.state[(93 + 91 - i_a) % 93];
        let s93 = &self.state[(93 + 92 - i_a) % 93];

        // --- register B ---
        let s162 = &self.state[93 + (84 + 68 - i_b) % 84];
        let s171 = &self.state[93 + (84 + 77 - i_b) % 84];
        let s175 = &self.state[93 + (84 + 81 - i_b) % 84];
        let s176 = &self.state[93 + (84 + 82 - i_b) % 84];
        let s177 = &self.state[93 + (84 + 83 - i_b) % 84];

        // --- register C ---
        let s243 = &self.state[177 + (111 + 65 - i_c) % 111];
        let s264 = &self.state[177 + (111 + 86 - i_c) % 111];
        let s286 = &self.state[177 + (111 + 108 - i_c) % 111];
        let s287 = &self.state[177 + (111 + 109 - i_c) % 111];
        let s288 = &self.state[177 + (111 + 110 - i_c) % 111];

        let mut t1 = GlweCiphertext::new(
            Scalar::ZERO,
            self.glwe_size,
            self.polynomial_size,
            self.ciphertext_modulus,
        );
        let mut t2 = GlweCiphertext::new(
            Scalar::ZERO,
            self.glwe_size,
            self.polynomial_size,
            self.ciphertext_modulus,
        );
        let mut t3 = GlweCiphertext::new(
            Scalar::ZERO,
            self.glwe_size,
            self.polynomial_size,
            self.ciphertext_modulus,
        );

        glwe_ciphertext_add(&mut t1, s66.glwe(), s93.glwe());
        glwe_ciphertext_add_assign(&mut t1, s171.glwe());
        if s91.is_ggsw() {
            convert_standard_ggsw_ciphertext_to_fourier(
                s91.ggsw(),
                &mut self.fourier_ggsw_buffer.as_mut_view(),
            );
            let stack = self.buffer.stack();
            add_external_product_assign_lead_one(
                t1.as_mut_view(),
                self.fourier_ggsw_buffer.as_view(),
                s92.glwe_view(),
                fft_view,
                stack,
            );
        } else if s92.is_ggsw() {
            convert_standard_ggsw_ciphertext_to_fourier(
                s92.ggsw(),
                &mut self.fourier_ggsw_buffer.as_mut_view(),
            );
            let stack = self.buffer.stack();
            add_external_product_assign_lead_one(
                t1.as_mut_view(),
                self.fourier_ggsw_buffer.as_view(),
                s91.glwe_view(),
                fft_view,
                stack,
            );
        } else {
            println!("both s91 and s92 are glwe, this should not happen in a correct execution");
        }

        glwe_ciphertext_add(&mut t2, s162.glwe(), s177.glwe());
        glwe_ciphertext_add_assign(&mut t2, s264.glwe());
        if s175.is_ggsw() {
            convert_standard_ggsw_ciphertext_to_fourier(
                s175.ggsw(),
                &mut self.fourier_ggsw_buffer.as_mut_view(),
            );
            let stack = self.buffer.stack();
            add_external_product_assign_lead_one(
                t1.as_mut_view(),
                self.fourier_ggsw_buffer.as_view(),
                s176.glwe_view(),
                fft_view,
                stack,
            );
        } else if s176.is_ggsw() {
            convert_standard_ggsw_ciphertext_to_fourier(
                s176.ggsw(),
                &mut self.fourier_ggsw_buffer.as_mut_view(),
            );
            let stack = self.buffer.stack();
            add_external_product_assign_lead_one(
                t1.as_mut_view(),
                self.fourier_ggsw_buffer.as_view(),
                s175.glwe_view(),
                fft_view,
                stack,
            );
        } else {
            println!("both s175 and s176 are glwe, this should not happen in a correct execution");
        }

        glwe_ciphertext_add(&mut t3, s243.glwe(), s288.glwe());
        glwe_ciphertext_add_assign(&mut t3, s69.glwe());
        if s286.is_ggsw() {
            convert_standard_ggsw_ciphertext_to_fourier(
                s286.ggsw(),
                &mut self.fourier_ggsw_buffer.as_mut_view(),
            );
            let stack = self.buffer.stack();
            add_external_product_assign_lead_one(
                t1.as_mut_view(),
                self.fourier_ggsw_buffer.as_view(),
                s287.glwe_view(),
                fft_view,
                stack,
            );
        } else if s287.is_ggsw() {
            convert_standard_ggsw_ciphertext_to_fourier(
                s287.ggsw(),
                &mut self.fourier_ggsw_buffer.as_mut_view(),
            );
            let stack = self.buffer.stack();
            add_external_product_assign_lead_one(
                t1.as_mut_view(),
                self.fourier_ggsw_buffer.as_view(),
                s286.glwe_view(),
                fft_view,
                stack,
            );
        } else {
            println!("both s286 and s287 are glwe, this should not happen in a correct execution");
        }

        let write_a_idx = (93 + 92 - i_a) % 93;
        let write_b_idx = 93 + (84 + 83 - i_b) % 84;
        let write_c_idx = 177 + (111 + 110 - i_c) % 111;

        self.state[write_a_idx]
            .glwe_mut()
            .as_mut()
            .copy_from_slice(t3.as_ref());
        self.state[write_a_idx].set_data_type_glwe();

        self.state[write_b_idx]
            .glwe_mut()
            .as_mut()
            .copy_from_slice(t1.as_ref());
        self.state[write_b_idx].set_data_type_glwe();

        self.state[write_c_idx]
            .glwe_mut()
            .as_mut()
            .copy_from_slice(t2.as_ref());
        self.state[write_c_idx].set_data_type_glwe();

        if refresh {
            self.state[write_a_idx].cbs_glwe_to_ggsw(fourier_bsk, auto_keys, ss_key, ksk, parms);
            self.state[write_b_idx].cbs_glwe_to_ggsw(fourier_bsk, auto_keys, ss_key, ksk, parms);
            self.state[write_c_idx].cbs_glwe_to_ggsw(fourier_bsk, auto_keys, ss_key, ksk, parms);
            self.state[write_a_idx].set_data_type_ggsw();
            self.state[write_b_idx].set_data_type_ggsw();
            self.state[write_c_idx].set_data_type_ggsw();
        }
        self.index += 1;
    }

    pub fn run(
        &mut self,
        num_steps: usize,
        fourier_bsk: FourierLweBootstrapKeyView<'_>,
        auto_keys: &HashMap<usize, AutomorphKey<ABox<[c64]>>>,
        ss_key: FourierGgswCiphertextListView,
        ksk: &LweStoredReusedKeyswitchKey<Vec<Scalar>>,
        parms: &ProcessorParam<Scalar>,
    ) -> Vec<LweCiphertextOwned<Scalar>>

    {
        let mut result = vec![self.large_lwe_buffer.clone(); num_steps];
        for i in 0..num_steps {
            let output = self.get_output_bit();
            extract_lwe_sample_from_glwe_ciphertext(&output, &mut result[i], MonomialDegree(0));
            self.next_state(true, fourier_bsk, auto_keys, ss_key, ksk, parms);
        }

        result
    }
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
