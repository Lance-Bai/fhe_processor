use itertools::izip;
use pulp::{c64};
use tfhe::core_crypto::prelude::Split;

// 注意：原库的 into_chunks 可能是自定义的，这里我们改用标准库的 chunks_exact
pub fn update_with_fmadd_local(
    output_fft_buffer: &mut [c64],
    lhs_polynomial_list: &[c64],
    fourier: &[c64],
    is_output_uninit: bool,
    fourier_poly_size: usize,
) {
    struct Impl<'a> {
        output_fft_buffer: &'a mut [c64],
        lhs_polynomial_list: &'a [c64],
        fourier: &'a [c64],
        is_output_uninit: bool,
        fourier_poly_size: usize,
    }

    impl pulp::WithSimd for Impl<'_> {
        type Output = ();

        #[inline(always)]
        fn with_simd<S: pulp::Simd>(self, simd: S) -> Self::Output {
            // Introducing a function boundary here means that the slices
            // get `noalias` markers, possibly allowing better optimizations from LLVM.
            //
            // see:
            // https://github.com/rust-lang/rust/blob/56e1aaadb31542b32953292001be2312810e88fd/library/core/src/slice/mod.rs#L960-L966
            #[inline(always)]
            fn implementation<S: pulp::Simd>(
                simd: S,
                output_fft_buffer: &mut [c64],
                lhs_polynomial_list: &[c64],
                fourier: &[c64],
                is_output_uninit: bool,
                fourier_poly_size: usize,
            ) {
                let rhs = S::c64s_as_simd(fourier).0;

                if is_output_uninit {
                    for (output_fourier, ggsw_poly) in izip!(
                        output_fft_buffer.into_chunks(fourier_poly_size),
                        lhs_polynomial_list.into_chunks(fourier_poly_size)
                    ) {
                        let out = S::c64s_as_mut_simd(output_fourier).0;
                        let lhs = S::c64s_as_simd(ggsw_poly).0;

                        for (out, &lhs, &rhs) in izip!(out, lhs, rhs) {
                            *out = simd.c64s_mul(lhs, rhs);
                        }
                    }
                } else {
                    for (output_fourier, ggsw_poly) in izip!(
                        output_fft_buffer.into_chunks(fourier_poly_size),
                        lhs_polynomial_list.into_chunks(fourier_poly_size)
                    ) {
                        let out = S::c64s_as_mut_simd(output_fourier).0;
                        let lhs = S::c64s_as_simd(ggsw_poly).0;

                        for (out, &lhs, &rhs) in izip!(out, lhs, rhs) {
                            *out = simd.c64s_mul_add_e(lhs, rhs, *out);
                        }
                    }
                }
            }

            implementation(
                simd,
                self.output_fft_buffer,
                self.lhs_polynomial_list,
                self.fourier,
                self.is_output_uninit,
                self.fourier_poly_size,
            );
        }
    }

    pulp::Arch::new().dispatch(Impl {
        output_fft_buffer,
        lhs_polynomial_list,
        fourier,
        is_output_uninit,
        fourier_poly_size,
    });
}