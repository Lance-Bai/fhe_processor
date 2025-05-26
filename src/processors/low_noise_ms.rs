use tfhe::core_crypto::prelude::{Container, ContainerMut, LweCiphertext, UnsignedInteger};

pub fn lwe_ciphertext_mod_switch_from_native_to_non_native_power_of_two_with_low_noise<
    Scalar,
    InputCont,
    OutputCont,
>(
    input: &LweCiphertext<InputCont>,
    output: &mut LweCiphertext<OutputCont>,
) where
    Scalar: UnsignedInteger,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    assert!(
        input.ciphertext_modulus().is_native_modulus(),
        "input ciphertext modulus is not native"
    );
    assert!(
        output.ciphertext_modulus().is_non_native_power_of_two(),
        "output ciphertext modulus is not non-native power-of-two"
    );

    let output_ciphertext_modulus = output.ciphertext_modulus();
    let divisor = output_ciphertext_modulus.get_power_of_two_scaling_to_native_torus();

    let (in_mask, in_body) = input.get_mask_and_body();
    let (mut out_mask, mut out_body) = output.get_mut_mask_and_body();
    let mut bias: Scalar = Scalar::ZERO;
    for (src, dst) in in_mask.as_ref().iter().zip(out_mask.as_mut().iter_mut()) {
        *dst = *src - (*src) % divisor;
        bias += *src - *dst;
    }
    //fix the body with bias with b' = b - mu * bias
    in_body.data.clone_into(&mut out_body.data);
    let fixed_b = *in_body.data - bias >> 1;
    *out_body.data = fixed_b - fixed_b % divisor;
}
