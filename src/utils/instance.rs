use super::parms::ProcessorParam;
use refined_tfhe_lhe::FftType;
use lazy_static::lazy_static;
use tfhe::core_crypto::prelude::*;

lazy_static! {

    pub static ref ZeroNoiseTest: ProcessorParam<u64> = ProcessorParam::new(
        LweDimension(873), // lwe_dimension
        StandardDev(0.00000000000000000000000000000000000000000000001), // lwe_modular_std_dev
        PolynomialSize(2048), // polynomial_size
        GlweDimension(1), // glwe_dimension
        GlweDimension(2), // large_glwe_dimension
        StandardDev(0.00000000000000000000000000000000000000000000000000000001), // glwe_modular_std_dev
        StandardDev(0.000000000000000000000000000000000000000000000000000000001), // large_glwe_modular_std_dev
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
    pub static ref ZeroNoiseTestII: ProcessorParam<u64> = ProcessorParam::new(
        LweDimension(512), // lwe_dimension
        StandardDev(0.00000000000000000000000000000000000000000000001), // lwe_modular_std_dev
        PolynomialSize(2048), // polynomial_size
        GlweDimension(1), // glwe_dimension
        GlweDimension(2), // large_glwe_dimension
        StandardDev(0.00000000000000000000000000000000000000000000000000000001), // glwe_modular_std_dev
        StandardDev(0.000000000000000000000000000000000000000000000000000000001), // large_glwe_modular_std_dev
        DecompositionBaseLog(9), // pbs_base_log
        DecompositionLevelCount(4), // pbs_level
        DecompositionBaseLog(4), // ks_base_log
        DecompositionLevelCount(4), // ks_level
        DecompositionBaseLog(15), // glwe_ds_to_large_base_log
        DecompositionLevelCount(3), // glwe_ds_to_large_level
        FftType::Split(44), // fft_type_to_large
        DecompositionBaseLog(6), // auto_base_log
        DecompositionLevelCount(8), // auto_level
        FftType::Split(35), // fft_type_auto
        DecompositionBaseLog(13), // glwe_ds_from_large_base_log
        DecompositionLevelCount(3), // glwe_ds_from_large_level
        FftType::Split(42), // fft_type_from_large
        DecompositionBaseLog(6), // ss_base_log
        DecompositionLevelCount(8), // ss_level
        DecompositionBaseLog(6), // cbs_base_log
        DecompositionLevelCount(4), // cbs_level
        LutCountLog(1), // log_lut_count
        CiphertextModulus::<u64>::new_native(), // ciphertext_modulus
        4, // message_size
        4,
    );
    pub static ref SetI: ProcessorParam<u64> = ProcessorParam::new(
        LweDimension(710), // lwe_dimension
        StandardDev(2.09820e-5), // lwe_modular_std_dev
        PolynomialSize(1024), // polynomial_size
        GlweDimension(2), // glwe_dimension
        GlweDimension(0), // large_glwe_dimension
        StandardDev(2.94036e-16), // glwe_modular_std_dev
        StandardDev(0.000000000000000000000000000000000000000000000000000000001), // large_glwe_modular_std_dev
        DecompositionBaseLog(12), // pbs_base_log
        DecompositionLevelCount(3), // pbs_level
        DecompositionBaseLog(4), // ks_base_log
        DecompositionLevelCount(4), // ks_level
        DecompositionBaseLog(1), // glwe_ds_to_large_base_log
        DecompositionLevelCount(1), // glwe_ds_to_large_level
        FftType::Split(38), // fft_type_to_large
        DecompositionBaseLog(10), // auto_base_log
        DecompositionLevelCount(4), // auto_level
        FftType::Split(38), // fft_type_auto
        DecompositionBaseLog(13), // glwe_ds_from_large_base_log
        DecompositionLevelCount(3), // glwe_ds_from_large_level
        FftType::Split(38), // fft_type_from_large
        DecompositionBaseLog(13), // ss_base_log
        DecompositionLevelCount(3), // ss_level
        DecompositionBaseLog(8), // cbs_base_log
        DecompositionLevelCount(2), // cbs_level
        LutCountLog(1), // log_lut_count
        CiphertextModulus::<u64>::new_native(), // ciphertext_modulus
        4, // message_size
        4,
    );

    pub static ref SetI_small: ProcessorParam<u64> = ProcessorParam::new(
        LweDimension(710), // lwe_dimension
        StandardDev(2.09820e-5), // lwe_modular_std_dev
        PolynomialSize(2048), // polynomial_size
        GlweDimension(1), // glwe_dimension
        GlweDimension(0), // large_glwe_dimension
        StandardDev(2.94036e-16), // glwe_modular_std_dev
        StandardDev(0.000000000000000000000000000000000000000000000000000000001), // large_glwe_modular_std_dev
        DecompositionBaseLog(15), // pbs_base_log
        DecompositionLevelCount(2), // pbs_level
        DecompositionBaseLog(4), // ks_base_log
        DecompositionLevelCount(4), // ks_level
        DecompositionBaseLog(1), // glwe_ds_to_large_base_log
        DecompositionLevelCount(1), // glwe_ds_to_large_level
        FftType::Split(38), // fft_type_to_large
        DecompositionBaseLog(17), // auto_base_log
        DecompositionLevelCount(2), // auto_level
        FftType::Split(34), // fft_type_auto
        DecompositionBaseLog(13), // glwe_ds_from_large_base_log
        DecompositionLevelCount(3), // glwe_ds_from_large_level
        FftType::Split(38), // fft_type_from_large
        DecompositionBaseLog(17), // ss_base_log
        DecompositionLevelCount(2), // ss_level
        DecompositionBaseLog(4), // cbs_base_log
        DecompositionLevelCount(4), // cbs_level
        LutCountLog(2), // log_lut_count
        CiphertextModulus::<u64>::new_native(), // ciphertext_modulus
        4, // message_size
        4,
    );

        pub static ref SetI_large: ProcessorParam<u64> = ProcessorParam::new(
        LweDimension(710), // lwe_dimension
        StandardDev(2.09820e-5), // lwe_modular_std_dev
        PolynomialSize(1024), // polynomial_size
        GlweDimension(2), // glwe_dimension
        GlweDimension(0), // large_glwe_dimension
        StandardDev(2.94036e-16), // glwe_modular_std_dev
        StandardDev(0.000000000000000000000000000000000000000000000000000000001), // large_glwe_modular_std_dev
        DecompositionBaseLog(5), // pbs_base_log
        DecompositionLevelCount(9), // pbs_level
        DecompositionBaseLog(4), // ks_base_log
        DecompositionLevelCount(4), // ks_level
        DecompositionBaseLog(1), // glwe_ds_to_large_base_log
        DecompositionLevelCount(1), // glwe_ds_to_large_level
        FftType::Split(38), // fft_type_to_large
        DecompositionBaseLog(4), // auto_base_log
        DecompositionLevelCount(12), // auto_level
        FftType::Split(38), // fft_type_auto
        DecompositionBaseLog(13), // glwe_ds_from_large_base_log
        DecompositionLevelCount(3), // glwe_ds_from_large_level
        FftType::Split(38), // fft_type_from_large
        DecompositionBaseLog(8), // ss_base_log
        DecompositionLevelCount(6), // ss_level
        DecompositionBaseLog(16), // cbs_base_log
        DecompositionLevelCount(1), // cbs_level
        LutCountLog(0), // log_lut_count
        CiphertextModulus::<u64>::new_native(), // ciphertext_modulus
        4, // message_size
        4,
    );


        pub static ref SetII: ProcessorParam<u64> = ProcessorParam::new(
        LweDimension(710), // lwe_dimension
        StandardDev(2.09820e-5), // lwe_modular_std_dev
        PolynomialSize(1024), // polynomial_size
        GlweDimension(2), // glwe_dimension
        GlweDimension(0), // large_glwe_dimension
        StandardDev(2.94036e-16), // glwe_modular_std_dev
        StandardDev(0.000000000000000000000000000000000000000000000000000000001), // large_glwe_modular_std_dev
        DecompositionBaseLog(12), // pbs_base_log
        DecompositionLevelCount(3), // pbs_level
        DecompositionBaseLog(4), // ks_base_log
        DecompositionLevelCount(4), // ks_level
        DecompositionBaseLog(1), // glwe_ds_to_large_base_log
        DecompositionLevelCount(1), // glwe_ds_to_large_level
        FftType::Split(38), // fft_type_to_large
        DecompositionBaseLog(10), // auto_base_log
        DecompositionLevelCount(4), // auto_level
        FftType::Split(38), // fft_type_auto
        DecompositionBaseLog(13), // glwe_ds_from_large_base_log
        DecompositionLevelCount(3), // glwe_ds_from_large_level
        FftType::Split(38), // fft_type_from_large
        DecompositionBaseLog(13), // ss_base_log
        DecompositionLevelCount(3), // ss_level
        DecompositionBaseLog(8), // cbs_base_log
        DecompositionLevelCount(2), // cbs_level
        LutCountLog(1), // log_lut_count
        CiphertextModulus::<u64>::new_native(), // ciphertext_modulus
        2, // message_size
        2,
    );

}
