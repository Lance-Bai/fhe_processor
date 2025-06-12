use super::parms::ProcessorParam;
use auto_base_conv::FftType;
use lazy_static::lazy_static;
use tfhe::core_crypto::prelude::*;

lazy_static! {
        pub static ref Processor_4_bits: ProcessorParam<u64> = ProcessorParam::new(
        LweDimension(873), // lwe_dimension
        StandardDev(0.0000006428797112843789), // lwe_modular_std_dev
        PolynomialSize(2048), // polynomial_size
        GlweDimension(1), // glwe_dimension
        GlweDimension(2), // large_glwe_dimension
        StandardDev(0.00000000000000029403601535432533), // glwe_modular_std_dev
        StandardDev(0.0000000000000000002168404344971009), // large_glwe_modular_std_dev
        DecompositionBaseLog(11), // pbs_base_log
        DecompositionLevelCount(3), // pbs_level
        DecompositionBaseLog(7), // ks_base_log
        DecompositionLevelCount(2), // ks_level
        DecompositionBaseLog(15), // glwe_ds_to_large_base_log
        DecompositionLevelCount(3), // glwe_ds_to_large_level
        FftType::Split(44), // fft_type_to_large
        DecompositionBaseLog(12), // auto_base_log
        DecompositionLevelCount(4), // auto_level
        FftType::Split(41), // fft_type_auto
        DecompositionBaseLog(13), // glwe_ds_from_large_base_log
        DecompositionLevelCount(3), // glwe_ds_from_large_level
        FftType::Split(42), // fft_type_from_large
        DecompositionBaseLog(10), // ss_base_log
        DecompositionLevelCount(4), // ss_level
        DecompositionBaseLog(5), // cbs_base_log
        DecompositionLevelCount(4), // cbs_level
        LutCountLog(2), // log_lut_count
        CiphertextModulus::<u64>::new_native(), // ciphertext_modulus
        4, // message_size
        4,
    );

        pub static ref ZeroNoiseTest: ProcessorParam<u64> = ProcessorParam::new(
        LweDimension(873), // lwe_dimension
        StandardDev(0.000000000000000000000000000000000001), // lwe_modular_std_dev
        PolynomialSize(2048), // polynomial_size
        GlweDimension(1), // glwe_dimension
        GlweDimension(2), // large_glwe_dimension
        StandardDev(0.00000000000000000000000000000000000000000000001), // glwe_modular_std_dev
        StandardDev(0.0000000000000000000000000000000000000000000000001), // large_glwe_modular_std_dev
        DecompositionBaseLog(11), // pbs_base_log
        DecompositionLevelCount(3), // pbs_level
        DecompositionBaseLog(7), // ks_base_log
        DecompositionLevelCount(2), // ks_level
        DecompositionBaseLog(15), // glwe_ds_to_large_base_log
        DecompositionLevelCount(3), // glwe_ds_to_large_level
        FftType::Split(44), // fft_type_to_large
        DecompositionBaseLog(12), // auto_base_log
        DecompositionLevelCount(4), // auto_level
        FftType::Split(41), // fft_type_auto
        DecompositionBaseLog(13), // glwe_ds_from_large_base_log
        DecompositionLevelCount(3), // glwe_ds_from_large_level
        FftType::Split(42), // fft_type_from_large
        DecompositionBaseLog(10), // ss_base_log
        DecompositionLevelCount(4), // ss_level
        DecompositionBaseLog(5), // cbs_base_log
        DecompositionLevelCount(4), // cbs_level
        LutCountLog(2), // log_lut_count
        CiphertextModulus::<u64>::new_native(), // ciphertext_modulus
        4, // message_size
        4,
    );
}
