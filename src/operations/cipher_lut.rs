use aligned_vec::CACHELINE_ALIGN;
use dyn_stack::{PodStack, ReborrowMut};
use itertools::izip;
use jemalloc_ctl::opt::zero;
use tfhe::core_crypto::fft_impl::fft64::math::polynomial::FourierPolynomialMutView;
use tfhe::core_crypto::prelude::polynomial_algorithms::polynomial_wrapping_monic_monomial_div_assign;
use tfhe::core_crypto::prelude::Polynomial;
use tfhe::{
    boolean::prelude::PolynomialSize,
    core_crypto::{
        commons::math::decomposition::DecompositionLevel,
        prelude::{
            ComputationBuffers, Fft, FourierGgswCiphertextList, LweCiphertext, PolynomialList,
            Split,
        },
    },
};
use tfhe::{
    boolean::prelude::{DecompositionBaseLog, DecompositionLevelCount},
    core_crypto::{
        fft_impl::fft64::{
            c64,
            crypto::{
                ggsw::{
                    add_external_product_assign, add_external_product_assign_scratch, cmux,
                    cmux_scratch, fill_with_forward_fourier_scratch,
                    FourierGgswCiphertextListMutView, FourierGgswCiphertextListView,
                    FourierGgswCiphertextView,
                },
                wop_pbs::{
                    cmux_tree_memory_optimized_scratch, vertical_packing, vertical_packing_scratch,
                },
            },
            math::{decomposition::TensorSignedDecompositionLendingIter, fft::FftView},
        },
        prelude::{
            extract_lwe_sample_from_glwe_ciphertext, CastInto, ContiguousEntityContainer,
            ContiguousEntityContainerMut, GlweCiphertext, GlweCiphertextList,
            GlweCiphertextMutView, GlweCiphertextView, MonomialDegree, SignedDecomposer,
            UnsignedTorus,
        },
    },
};

use crate::{
    processors::decomposer::TensorSignedDecompositionLendingIterLocal,
    utils::fmadd::update_with_fmadd_local,
};
/// Pack multiple lookup tables into encrypted lookup tables
/// (each lookup table is independently generated as a `PolynomialList`).
///
/// # Parameters
/// - `tables`: A collection of lookup tables, where each element is one table
///   (e.g., different chunked sub-tables or different functional tables).
/// - `polynomial_size`: The polynomial degree (how many elements can fit
///   in each GLWE polynomial).
/// - `delta`: Scaling factor (used in TFHE encoding).
///
/// # Returns
/// - `Vec<PolynomialList<Vec<u64>>>`: A vector of encrypted lookup tables,
///   where each table corresponds to one `PolynomialList`.
///
/// # Example
/// ```ignore
/// let lut_lists = generate_lut_from_vecs(&split_tables, PolynomialSize(1024), 1 << 40);
/// // `lut_lists[i]` is the encrypted lookup table (PolynomialList) for the i-th table.
/// ```
pub fn generate_lut_from_vecs(
    tables: &[Vec<usize>],
    polynomial_size: PolynomialSize,
    delta: u64,
) -> Vec<PolynomialList<Vec<u64>>> {
    let mut result = Vec::with_capacity(tables.len());

    for (_, table) in tables.iter().enumerate() {
        let table_len = table.len();
        let num_poly = (table_len + polynomial_size.0 - 1) / polynomial_size.0;

        let mut flat: Vec<u64> = Vec::with_capacity(num_poly * polynomial_size.0);

        for poly_idx in 0..num_poly {
            for i in 0..polynomial_size.0 {
                let idx = poly_idx * polynomial_size.0 + i;
                let val = if idx < table_len {
                    (table[idx] as u64) * delta
                } else {
                    0
                };
                flat.push(val);
            }
        }

        let poly_list = PolynomialList::from_container(flat, polynomial_size);
        result.push(poly_list);
    }
    result
}

pub fn generate_lut_from_vecs_auto(
    tables: &[Vec<usize>],
    polynomial_size: PolynomialSize,
    delta: u64,
) -> (Vec<PolynomialList<Vec<u64>>>, usize) {
    assert!(!tables.is_empty(), "tables must not be empty");

    let table_len = tables[0].len();
    for t in tables.iter().skip(1) {
        assert!(
            t.len() == table_len,
            "all tables must have the same length: expected {}, got {}",
            table_len,
            t.len()
        );
    }

    let n = polynomial_size.0;
    let per_poly_capacity = n / table_len;

    // no packing
    if per_poly_capacity < 1 {
        let mut result = Vec::with_capacity(tables.len());

        for table in tables {
            let table_len = table.len();
            let num_poly = (table_len + n - 1) / n;

            let mut flat: Vec<u64> = Vec::with_capacity(num_poly * n);

            for poly_idx in 0..num_poly {
                for i in 0..n {
                    let idx = poly_idx * n + i;
                    let val = if idx < table_len {
                        (table[idx] as u64) * delta
                    } else {
                        0
                    };
                    flat.push(val);
                }
            }

            let poly_list = PolynomialList::from_container(flat, polynomial_size);
            result.push(poly_list);
        }

        return (result, 1);
    }

    // with packing
    let total_tables = tables.len();
    let num_groups = (total_tables + per_poly_capacity - 1) / per_poly_capacity;

    let mut result = Vec::with_capacity(num_groups);

    for g in 0..num_groups {
        let mut flat = vec![0u64; n];

        for s in 0..per_poly_capacity {
            let table_idx = g * per_poly_capacity + s;
            if table_idx >= total_tables {
                break;
            }

            // copy to [s*table_len .. s*table_len + table_len)
            let slot_base = s * table_len;
            let table = &tables[table_idx];

            for j in 0..table_len {
                flat[slot_base + j] = (table[j] as u64) * delta;
            }
        }

        let poly_list = PolynomialList::from_container(flat, polynomial_size);
        //now poly_list contain 1 poly only
        result.push(poly_list);
    }

    (result, per_poly_capacity)
}

/// TFHE vertical_packing lookup function for a single lookup table
///
/// # Parameters
/// - `lut`: The lookup table (`PolynomialList`)
/// - `lwe_out`: Output ciphertext (`LweCiphertext`, mutable)
/// - `ggsw_list`: GGSW key list
/// - `fft`: FFT context
/// - `buffer`: Temporary scratch buffer
/// - `lut_input_size`: Number of input bits (or total inputs) for the lookup table;
///   must match the GLWE parameters
///
/// # Description
/// Performs a complete lookup using vertical_packing.
/// The result is written into `lwe_out`.
pub fn tfhe_vertical_packing_lookup(
    lut: &PolynomialList<Vec<u64>>,
    lwe_out: &mut LweCiphertext<Vec<u64>>,
    ggsw_list: &FourierGgswCiphertextList<Vec<c64>>,
    fft: &Fft,
    buffer: &mut ComputationBuffers,
    lut_input_size: usize,
) {
    let _ = lut_input_size;
    // 确保buffer大小足够
    buffer.resize(
        vertical_packing_scratch::<u64>(
            ggsw_list.glwe_size(),
            ggsw_list.polynomial_size(),
            lut.polynomial_count(),
            ggsw_list.count(),
            fft.as_view(),
        )
        .unwrap()
        .unaligned_bytes_required(),
    );
    let stack = buffer.stack();

    vertical_packing(
        lut.as_view(),
        lwe_out.as_mut_view(),
        ggsw_list.as_view(),
        fft.as_view(),
        stack,
    );
}

/// Batch vertical_packing lookup for multiple lookup tables
///
/// # Parameters
/// - `luts`: Array of lookup tables (each a `PolynomialList`)
/// - `lwe_outs`: Array of output ciphertexts (each an `LweCiphertext`)
/// - Others: Same as above
pub fn tfhe_vertical_packing_multi_lookup(
    luts: &[PolynomialList<Vec<u64>>],
    lwe_outs: &mut [LweCiphertext<Vec<u64>>],
    ggsw_list: &FourierGgswCiphertextList<Vec<c64>>,
    fft: &Fft,
    buffer: &mut ComputationBuffers,
    lut_input_size: usize,
) {
    assert_eq!(luts.len(), lwe_outs.len());
    for (lut, lwe_out) in luts.iter().zip(lwe_outs.iter_mut()) {
        tfhe_vertical_packing_lookup(lut, lwe_out, ggsw_list, fft, buffer, lut_input_size);
    }
}

// GGSW ciphertexts are stored from the msb (vec_ggsw[0]) to the lsb (vec_ggsw[last])
pub fn opmized_vertical_packing<Scalar: UnsignedTorus + CastInto<usize>>(
    lut: PolynomialList<&[Scalar]>,
    mut lwe_out: LweCiphertext<&mut [Scalar]>,
    ggsw_list: FourierGgswCiphertextListView<'_>,
    fft: FftView<'_>,
    stack: PodStack<'_>,
    zero_mask: bool,
) {
    debug_assert!(
        lwe_out.ciphertext_modulus().is_native_modulus(),
        "This operation currently only supports native moduli"
    );

    let polynomial_size = ggsw_list.polynomial_size();
    let glwe_size = ggsw_list.glwe_size();
    let glwe_dimension = glwe_size.to_glwe_dimension();
    let ciphertext_modulus = lwe_out.ciphertext_modulus();

    debug_assert!(
        lwe_out.lwe_size().to_lwe_dimension()
            == glwe_dimension.to_equivalent_lwe_dimension(polynomial_size),
        "Output LWE ciphertext needs to have an LweDimension of {:?}, got {:?}",
        glwe_dimension.to_equivalent_lwe_dimension(polynomial_size),
        lwe_out.lwe_size().to_lwe_dimension(),
    );

    // Get the base 2 logarithm (rounded down) of the number of polynomials in the list i.e. if
    // there is one polynomial, the number will be 0
    let log_lut_number: usize =
        Scalar::BITS - 1 - lut.polynomial_count().0.leading_zeros() as usize;

    let log_number_of_luts_for_cmux_tree = if log_lut_number > ggsw_list.count() {
        // this means that we dont have enough GGSW to perform the CMux tree, we can only do the
        // Blind rotation
        0
    } else {
        log_lut_number
    };

    // split the vec of GGSW in two, the msb GGSW is for the CMux tree and the lsb GGSW is for
    // the last blind rotation.
    let (cmux_ggsw, br_ggsw) = ggsw_list.split_at(log_number_of_luts_for_cmux_tree);

    let (mut cmux_tree_lut_res_data, mut stack) =
        stack.make_aligned_with(polynomial_size.0 * glwe_size.0, CACHELINE_ALIGN, |_| {
            Scalar::ZERO
        });
    let mut cmux_tree_lut_res = GlweCiphertext::from_container(
        &mut *cmux_tree_lut_res_data,
        polynomial_size,
        ciphertext_modulus,
    );

    cmux_tree_uniform_optimized(
        cmux_tree_lut_res.as_mut_view(),
        lut,
        cmux_ggsw,
        fft,
        stack.rb_mut(),
    );
    blind_rotate_assign_local(
        cmux_tree_lut_res.as_mut_view(),
        br_ggsw,
        fft,
        stack.rb_mut(),
        cmux_ggsw.count() == 0,
    );

    // sample extract of the RLWE of the Vertical packing
    extract_lwe_sample_from_glwe_ciphertext(&cmux_tree_lut_res, &mut lwe_out, MonomialDegree(0));
}

pub fn cmux_tree_uniform_optimized<Scalar: UnsignedTorus + CastInto<usize>>(
    mut output_glwe: GlweCiphertext<&mut [Scalar]>,
    lut_per_layer: PolynomialList<&[Scalar]>,
    ggsw_list: FourierGgswCiphertextListView<'_>,
    fft: FftView<'_>,
    stack: PodStack<'_>,
) {
    debug_assert!(lut_per_layer.polynomial_count().0 == 1 << ggsw_list.count());

    if ggsw_list.count() > 0 {
        let glwe_size = output_glwe.glwe_size();
        let ciphertext_modulus = output_glwe.ciphertext_modulus();
        let polynomial_size = ggsw_list.polynomial_size();
        let nb_layer = ggsw_list.count();

        debug_assert!(stack.can_hold(
            cmux_tree_memory_optimized_scratch::<Scalar>(glwe_size, polynomial_size, nb_layer, fft)
                .unwrap()
        ));

        // These are accumulator that will be used to propagate the result from layer to layer
        // At index 0 you have the lut that will be loaded, and then the result for each layer gets
        // computed at the next index, last layer result gets stored in `result`.
        // This allow to use memory space in C * nb_layer instead of C' * 2 ^ nb_layer
        let (mut t_0_data, stack) = stack.make_aligned_with(
            polynomial_size.0 * glwe_size.0 * nb_layer,
            CACHELINE_ALIGN,
            |_| Scalar::ZERO,
        );
        let (mut t_1_data, stack) = stack.make_aligned_with(
            polynomial_size.0 * glwe_size.0 * nb_layer,
            CACHELINE_ALIGN,
            |_| Scalar::ZERO,
        );

        let mut t_0 = GlweCiphertextList::from_container(
            t_0_data.as_mut(),
            glwe_size,
            polynomial_size,
            ciphertext_modulus,
        );
        let mut t_1 = GlweCiphertextList::from_container(
            t_1_data.as_mut(),
            glwe_size,
            polynomial_size,
            ciphertext_modulus,
        );

        let (mut t_fill, mut stack) = stack.make_with(nb_layer, |_| 0_usize);

        let mut lut_polynomial_iter = lut_per_layer.iter();
        loop {
            let even = lut_polynomial_iter.next();
            let odd = lut_polynomial_iter.next();

            let (Some(lut_2i), Some(lut_2i_plus_1)) = (even, odd) else {
                break;
            };

            let mut t_iter = izip!(t_0.iter_mut(), t_1.iter_mut(),).enumerate();

            let (mut j_counter, (mut t0_j, mut t1_j)) = t_iter.next().unwrap();

            t0_j.get_mut_body()
                .as_mut()
                .copy_from_slice(lut_2i.as_ref());

            t1_j.get_mut_body()
                .as_mut()
                .copy_from_slice(lut_2i_plus_1.as_ref());

            t_fill[0] = 2;

            for (j, ggsw) in ggsw_list.into_ggsw_iter().rev().enumerate() {
                if t_fill[j] == 2 {
                    let (diff_data, stack) = stack.rb_mut().collect_aligned(
                        CACHELINE_ALIGN,
                        izip!(t1_j.as_ref(), t0_j.as_ref()).map(|(&a, &b)| a.wrapping_sub(b)),
                    );
                    let diff = GlweCiphertext::from_container(
                        &*diff_data,
                        polynomial_size,
                        ciphertext_modulus,
                    );

                    if j < nb_layer - 1 {
                        let (j_counter_plus_1, (mut t_0_j_plus_1, mut t_1_j_plus_1)) =
                            t_iter.next().unwrap();

                        assert_eq!(j_counter, j);
                        assert_eq!(j_counter_plus_1, j + 1);

                        let mut output = if t_fill[j + 1] == 0 {
                            t_0_j_plus_1.as_mut_view()
                        } else {
                            t_1_j_plus_1.as_mut_view()
                        };

                        output.as_mut().copy_from_slice(t0_j.as_ref());
                        if j == 0 {
                            // this should be the trival ext prod
                            add_external_product_assign_trivial(output, ggsw, diff, fft, stack);
                        } else {
                            add_external_product_assign(output, ggsw, diff, fft, stack);
                        }
                        t_fill[j + 1] += 1;
                        t_fill[j] = 0;

                        drop(diff_data);

                        (j_counter, t0_j, t1_j) = (j_counter_plus_1, t_0_j_plus_1, t_1_j_plus_1);
                    } else {
                        assert_eq!(j, nb_layer - 1);
                        let mut output = output_glwe.as_mut_view();
                        output.as_mut().copy_from_slice(t0_j.as_ref());
                        add_external_product_assign(output, ggsw, diff, fft, stack);
                    }
                } else {
                    break;
                }
            }
        }
    } else {
        output_glwe.get_mut_mask().as_mut().fill(Scalar::ZERO);
        output_glwe
            .get_mut_body()
            .as_mut()
            .copy_from_slice(lut_per_layer.as_ref());
    }
}

pub fn add_external_product_assign_trivial<Scalar>(
    mut out: GlweCiphertextMutView<'_, Scalar>,
    ggsw: FourierGgswCiphertextView<'_>,
    glwe: GlweCiphertextView<Scalar>,
    fft: FftView<'_>,
    stack: PodStack<'_>,
) where
    Scalar: UnsignedTorus,
{
    // we check that the polynomial sizes match
    debug_assert_eq!(ggsw.polynomial_size(), glwe.polynomial_size());
    debug_assert_eq!(ggsw.polynomial_size(), out.polynomial_size());
    // we check that the glwe sizes match
    debug_assert_eq!(ggsw.glwe_size(), glwe.glwe_size());
    debug_assert_eq!(ggsw.glwe_size(), out.glwe_size());

    let align = CACHELINE_ALIGN;
    let fourier_poly_size = ggsw.polynomial_size().to_fourier_polynomial_size().0;

    // we round the input mask and body
    let decomposer = SignedDecomposer::<Scalar>::new(
        ggsw.decomposition_base_log(),
        ggsw.decomposition_level_count(),
    );

    let (mut output_fft_buffer, mut substack0) =
        stack.make_aligned_raw::<c64>(fourier_poly_size * ggsw.glwe_size().0, align);
    // output_fft_buffer is initially uninitialized, considered to be implicitly zero, to avoid
    // the cost of filling it up with zeros. `is_output_uninit` is set to `false` once
    // it has been fully initialized for the first time.
    let output_fft_buffer = &mut *output_fft_buffer;
    let mut is_output_uninit = true;
    {
        // ------------------------------------------------------
        // EXTERNAL PRODUCT IN FOURIER DOMAIN (BODY ONLY VERSION)
        // ------------------------------------------------------

        let glwe_size = ggsw.glwe_size().0;
        let body_index = glwe_size - 1;

        // Decompose ONLY the body polynomial
        let body = glwe.get_body();

        let (mut decomposition, mut substack1) = TensorSignedDecompositionLendingIterLocal::new(
            body.as_ref()
                .iter()
                .map(|s| decomposer.closest_representable(*s)),
            decomposer.base_log(),
            decomposer.level_count(),
            substack0.rb_mut(),
        );

        // Loop over decomposition levels (reverse to match iterator order)
        ggsw.into_levels().rev().for_each(|ggsw_decomp_matrix| {
            // Get next decomposition term for the BODY only
            let (glwe_level, body_decomp_term, mut substack2) =
                collect_next_term(&mut decomposition, &mut substack1, align);

            debug_assert_eq!(ggsw_decomp_matrix.decomposition_level(), glwe_level);

            // Get the GGSW row corresponding to the BODY
            let ggsw_body_row = ggsw_decomp_matrix
                .into_rows()
                .nth(body_index)
                .expect("invalid GGSW body row index");

            // Allocate Fourier buffer for body polynomial
            let (mut fourier, substack3) = substack2
                .rb_mut()
                .make_aligned_raw::<c64>(fourier_poly_size, align);

            // Forward FFT of decomposed body polynomial
            let fourier = fft
                .forward_as_integer(
                    FourierPolynomialMutView { data: &mut fourier },
                    Polynomial::from_container(&*body_decomp_term),
                    substack3,
                )
                .data;

            // Accumulate external product in Fourier domain
            update_with_fmadd_local(
                output_fft_buffer,
                ggsw_body_row.data(),
                fourier,
                is_output_uninit,
                fourier_poly_size,
            );

            is_output_uninit = false;
        });
    }
    // --------------------------------------------  TRANSFORMATION OF RESULT TO STANDARD DOMAIN
    // In this section, we bring the result from the fourier domain, back to the standard
    // domain, and add it to the output.
    //
    // We iterate over the polynomials in the output.
    if !is_output_uninit {
        izip!(
            out.as_mut_polynomial_list().iter_mut(),
            output_fft_buffer
                .into_chunks(fourier_poly_size)
                .map(|slice| FourierPolynomialMutView { data: slice }),
        )
        .for_each(|(out, fourier)| {
            // The fourier buffer is not re-used afterwards so we can use the in-place version of
            // the add_backward_as_torus function
            fft.add_backward_in_place_as_torus(out, fourier, substack0.rb_mut());
        });
    }
}

fn collect_next_term<'a, Scalar: UnsignedTorus>(
    decomposition: &mut TensorSignedDecompositionLendingIterLocal<'_, Scalar>,
    substack1: &'a mut PodStack,
    align: usize,
) -> (
    DecompositionLevel,
    dyn_stack::DynArray<'a, Scalar>,
    PodStack<'a>,
) {
    let (glwe_level, _, glwe_decomp_term) = decomposition.next_term().unwrap();
    let (glwe_decomp_term, substack2) = substack1.rb_mut().collect_aligned(align, glwe_decomp_term);
    (glwe_level, glwe_decomp_term, substack2)
}

pub fn blind_rotate_assign_local<Scalar: UnsignedTorus + CastInto<usize>>(
    mut lut: GlweCiphertext<&mut [Scalar]>,
    ggsw_list: FourierGgswCiphertextListView<'_>,
    fft: FftView<'_>,
    mut stack: PodStack<'_>,
    is_trival: bool,
) {
    let mut monomial_degree = MonomialDegree(1);

    for (i, ggsw) in ggsw_list.into_ggsw_iter().rev().enumerate() {
        let ct_0 = lut.as_mut_view();
        let (mut ct1_data, stack) = stack
            .rb_mut()
            .collect_aligned(CACHELINE_ALIGN, ct_0.as_ref().iter().copied());
        let mut ct_1 = GlweCiphertext::from_container(
            &mut *ct1_data,
            ct_0.polynomial_size(),
            ct_0.ciphertext_modulus(),
        );
        ct_1.as_mut_polynomial_list()
            .iter_mut()
            .for_each(|mut poly| {
                polynomial_wrapping_monic_monomial_div_assign(&mut poly, monomial_degree);
            });
        monomial_degree.0 <<= 1;
        // if i == 0 && is_trival{
        //     cmux_trivial(ct_0, ct_1, ggsw, fft, stack);
        // } else {
        //     cmux(ct_0, ct_1, ggsw, fft, stack);
        // }
        cmux(ct_0, ct_1, ggsw, fft, stack);
    }
}

pub fn cmux_trivial<Scalar: UnsignedTorus>(
    ct0: GlweCiphertextMutView<'_, Scalar>,
    mut ct1: GlweCiphertextMutView<'_, Scalar>,
    ggsw: FourierGgswCiphertextView<'_>,
    fft: FftView<'_>,
    stack: PodStack<'_>,
) {
    izip!(ct1.as_mut(), ct0.as_ref(),).for_each(|(c1, c0)| {
        *c1 = c1.wrapping_sub(*c0);
    });
    add_external_product_assign_trivial(ct0, ggsw, ct1.as_view(), fft, stack);
}
