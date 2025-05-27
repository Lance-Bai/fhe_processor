use tfhe::{
    boolean::prelude::PolynomialSize,
    core_crypto::prelude::{
        CastInto, Container, LutCountLog, LweCiphertext, ModulusSwitchOffset,
        MonomialDegree, UnsignedTorus,
    },
};

fn fast_low_noise_pbs_modulus_switch_mask<Scalar: UnsignedTorus + CastInto<usize>>(
    input: Scalar,
    poly_size: PolynomialSize,
    offset: ModulusSwitchOffset,
    lut_count_log: LutCountLog,
) -> (usize, Scalar) {
    // First, do the left shift (we discard the offset msb)
    let mut output = input << offset.0;
    // Start doing the right shift
    output >>= Scalar::BITS - poly_size.log2().0 - 2 + lut_count_log.0;
    // Do the rounding
    output += Scalar::ONE;
    // Finish the right shift
    output >>= 1;
    let bias =
        input - output << (Scalar::BITS - poly_size.log2().0 - 1 + lut_count_log.0 - offset.0);
    // Apply the lsb padding
    output <<= lut_count_log.0;
    (<Scalar as CastInto<usize>>::cast_into(output), bias)
}

fn fast_low_noise_pbs_modulus_switch_body<Scalar: UnsignedTorus + CastInto<usize>>(
    input: Scalar,
    bias: Scalar,
    poly_size: PolynomialSize,
    offset: ModulusSwitchOffset,
    lut_count_log: LutCountLog,
) -> usize
where
    Scalar: UnsignedTorus + CastInto<usize>,
{
    let mut output = input - bias >> 1; // b - mu * bias, mu = 1/2
    output <<= offset.0;
    output >>= Scalar::BITS - poly_size.log2().0 - 2 + lut_count_log.0;
    // Do the rounding
    output += Scalar::ONE;
    // Finish the right shift
    output >>= 1;
    // Apply the lsb padding
    output <<= lut_count_log.0;
    <Scalar as CastInto<usize>>::cast_into(output)
}

pub fn fast_low_noise_pbs_modulus_switch<Scalar, InputCont>(
    input: &LweCiphertext<InputCont>,
    poly_size: PolynomialSize,
    offset: ModulusSwitchOffset,
    lut_count_log: LutCountLog,
) -> (Vec<MonomialDegree>, MonomialDegree)
where
    Scalar: UnsignedTorus + CastInto<usize>,
    InputCont: Container<Element = Scalar>,
{
    let mut bias_acc: Scalar = Scalar::ZERO;

    let mut mask: Vec<MonomialDegree> =
        vec![MonomialDegree(0); input.lwe_size().to_lwe_dimension().0];

    for (element, degree) in input.get_mask().as_ref().iter().zip(mask.iter_mut()) {
        let (output, bias) =
            fast_low_noise_pbs_modulus_switch_mask(*element, poly_size, offset, lut_count_log);
        *degree = MonomialDegree(output);
        bias_acc += bias;
    }

    let body = MonomialDegree(fast_low_noise_pbs_modulus_switch_body(
        *input.get_body().data,
        bias_acc,
        poly_size,
        offset,
        lut_count_log,
    ));

    (mask, body)
}
