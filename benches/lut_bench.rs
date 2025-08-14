use std::collections::HashMap;
use std::env;
use std::fs::{create_dir_all, OpenOptions};
use std::io::{BufWriter, Write};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use aligned_vec::ABox;
use concrete_fft::c64;
// benches/lut_sizes.rs
use criterion::{black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use fhe_processor::operations::cipher_lut::generate_lut_from_vecs_auto;
use fhe_processor::operations::manager::concat_ggsw_lists;
use fhe_processor::operations::operation::horizontal_vertical_packing_without_extract;
use fhe_processor::operations::plain_lut::split_adjusted_lut_by_chunk;
use fhe_processor::processors::cbs_4_bits::circuit_bootstrapping_4_bits_at_once_rev_tr;
use fhe_processor::processors::key_gen::allocate_and_generate_new_reused_lwe_key;
use fhe_processor::processors::lwe_stored_ksk::{
    allocate_and_generate_new_stored_reused_lwe_keyswitch_key, LweStoredReusedKeyswitchKey,
};
use fhe_processor::{utils::instance::SetI, utils::parms::ProcessorParam};
use indicatif::{ProgressBar, ProgressStyle};
use rayon::iter::{
    IndexedParallelIterator, IntoParallelRefIterator, IntoParallelRefMutIterator, ParallelIterator,
};
use rayon::slice::ParallelSliceMut;
use rayon::ThreadPoolBuilder;
use refined_tfhe_lhe::{gen_all_auto_keys, generate_scheme_switching_key, AutomorphKey};
use tfhe::core_crypto::fft_impl::fft64::crypto::wop_pbs::vertical_packing_scratch;
use tfhe::core_crypto::prelude::{
    allocate_and_trivially_encrypt_new_lwe_ciphertext, extract_lwe_sample_from_glwe_ciphertext,
    MonomialDegree, PolynomialList,
};
use tfhe::core_crypto::{
    prelude::{
        allocate_and_encrypt_new_lwe_ciphertext, allocate_and_generate_new_binary_glwe_secret_key,
        allocate_and_generate_new_lwe_bootstrap_key, convert_standard_lwe_bootstrap_key_to_fourier,
        ActivatedRandomGenerator, ComputationBuffers, EncryptionRandomGenerator, Fft,
        FourierGgswCiphertextList, FourierLweBootstrapKey, FourierLweBootstrapKeyOwned,
        GlweSecretKey, LweCiphertext, Plaintext, SecretRandomGenerator,
    },
    seeders::new_seeder,
};
// 按你的工程实际引入：
// use crate::{vertical_packing_multi_lookup, LUTType, ...};

const SAMPLE_SIZE: usize = 10;

struct BenchCtx {
    // 运行时只读共享
    fourier_bsk: FourierLweBootstrapKeyOwned,
    auto_keys: HashMap<usize, AutomorphKey<ABox<[c64]>>>,
    ss_key: FourierGgswCiphertextList<Vec<c64>>,
    glwe_sk: GlweSecretKey<Vec<u64>>,
    ksk: LweStoredReusedKeyswitchKey<Vec<u64>>,
    params: ProcessorParam<u64>,
    // 视图或其他你要复用的只读对象...
}

// ---------- 工具：一次性做初始化 ----------
fn setup_ctx(param: ProcessorParam<u64>) -> BenchCtx {
    // 读取参数（与你给的一致）
    let lwe_dimension = param.lwe_dimension();
    let polynomial_size = param.polynomial_size();
    let glwe_dimension = param.glwe_dimension();
    let glwe_modular_std_dev = param.glwe_modular_std_dev();
    let pbs_base_log = param.pbs_base_log();
    let pbs_level = param.pbs_level();
    let ks_base_log = param.ks_base_log();
    let ks_level = param.ks_level();
    let auto_base_log = param.auto_base_log();
    let auto_level = param.auto_level();
    let auto_fft_type = param.fft_type_auto();
    let ss_base_log = param.ss_base_log();
    let ss_level = param.ss_level();
    let ciphertext_modulus = param.ciphertext_modulus();

    let mut boxed_seeder = new_seeder(); // 你已有的 seeder
    let seeder = boxed_seeder.as_mut();

    let mut secret_generator =
        SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());

    let mut encryption_generator =
        EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);

    // 生成密钥（与你给的流程相同）
    let glwe_sk = allocate_and_generate_new_binary_glwe_secret_key(
        glwe_dimension,
        polynomial_size,
        &mut secret_generator,
    );
    let glwe_lwe_sk = glwe_sk.as_lwe_secret_key();
    let lwe_sk_after_ks = allocate_and_generate_new_reused_lwe_key(&glwe_lwe_sk, lwe_dimension);
    let ksk = allocate_and_generate_new_stored_reused_lwe_keyswitch_key(
        &glwe_lwe_sk,
        &lwe_sk_after_ks,
        ks_base_log,
        ks_level,
        glwe_modular_std_dev,
        ciphertext_modulus,
        &mut encryption_generator,
    );

    let bsk = allocate_and_generate_new_lwe_bootstrap_key(
        &lwe_sk_after_ks,
        &glwe_sk,
        pbs_base_log,
        pbs_level,
        glwe_modular_std_dev,
        ciphertext_modulus,
        &mut encryption_generator,
    );

    let mut fourier_bsk = FourierLweBootstrapKey::new(
        bsk.input_lwe_dimension(),
        bsk.glwe_size(),
        bsk.polynomial_size(),
        bsk.decomposition_base_log(),
        bsk.decomposition_level_count(),
    );
    convert_standard_lwe_bootstrap_key_to_fourier(&bsk, &mut fourier_bsk);
    drop(bsk);

    let auto_keys = gen_all_auto_keys(
        auto_base_log,
        auto_level,
        auto_fft_type,
        &glwe_sk,
        glwe_modular_std_dev,
        &mut encryption_generator,
    );

    let ss_key = generate_scheme_switching_key(
        &glwe_sk,
        ss_base_log,
        ss_level,
        glwe_modular_std_dev,
        ciphertext_modulus,
        &mut encryption_generator,
    );

    // 如果你需要一个空的（或占位）Fourier GGSW list，可在真正 case 里重建
    // 这里只保留参数

    BenchCtx {
        fourier_bsk,
        auto_keys: auto_keys,
        ss_key,
        glwe_sk,
        ksk,
        params: param,
    }
}

// ---------- 每个 n 的一次执行（只负责“计时的核心路径”） ----------
fn run_cbs_part(ctx: &BenchCtx, prep: &mut IterSetup) {
    let mut ggsw_lists = std::mem::take(&mut prep.fourier_ggsw_lists);

    let total_lwe = prep.lwes.len();
    // assert_eq!(ggsw_lists.len(), total_lwe, "LWE 数量与 GGSW 数量不一致");
    let fourier_bsk_view = ctx.fourier_bsk.as_view();
    let auto_keys = &ctx.auto_keys;
    let ss_key_view = ctx.ss_key.as_view();
    let params = &ctx.params;
    let ksk = &ctx.ksk;

    // 6) 并行执行：按 ggsw 的索引 i 取对应的 lwe 引用
    ggsw_lists
        .par_iter_mut()
        .enumerate()
        .take(total_lwe)
        .for_each(|(i, ggsw)| {
            let lwe = &prep.lwes[i];
            // 计算（每个线程只改它拿到的 ggsw；其余参数仅只读共享）
            circuit_bootstrapping_4_bits_at_once_rev_tr(
                &lwe,
                ggsw, // 已是 &mut
                fourier_bsk_view,
                auto_keys,
                ss_key_view,
                ksk,
                params,
            );
        });

    prep.fourier_ggsw_lists = ggsw_lists;
}

fn run_lut_part(ctx: &BenchCtx, prep: &mut IterSetup, n_bits: usize) {
    let input_bits = concat_ggsw_lists(prep.fourier_ggsw_lists.clone(), true);
    let ggsw_view = input_bits.as_view();
    let group_size = prep.pack_size.min(n_bits / ctx.params.extract_size());
    let lut_size = 1_usize << n_bits;
    let binding = Fft::new(ctx.params.polynomial_size());
    let fft_view = binding.as_view();
    prep.lut
        .par_iter()
        .zip(prep.lwe_outs.par_chunks_mut(group_size))
        .for_each(|(lut, lwe_group)| {
            let mut local_buffer = ComputationBuffers::new();
            let need = vertical_packing_scratch::<u64>(
                ggsw_view.glwe_size(),
                ggsw_view.polynomial_size(),
                lut.polynomial_count(),
                ggsw_view.count(),
                fft_view,
            )
            .unwrap()
            .unaligned_bytes_required();
            local_buffer.resize(need);

            let stack = local_buffer.stack();
            let temp = horizontal_vertical_packing_without_extract(
                lut.as_view(),
                ggsw_view,
                fft_view,
                stack,
                lwe_group[0].ciphertext_modulus(),
            );
            for (i, lwe) in lwe_group.iter_mut().enumerate() {
                extract_lwe_sample_from_glwe_ciphertext(&temp, lwe, MonomialDegree(i * lut_size));
            }
        });
}

struct IterSetup {
    // LWE 输入（数量 = n_bits/4）
    lwes: Vec<LweCiphertext<Vec<u64>>>,
    // GGSW 容器（外部分配内存，计时阶段只写入）
    fourier_ggsw_lists: Vec<FourierGgswCiphertextList<Vec<c64>>>,
    // 输出 LWE（长度按你的查表策略决定）
    lwe_outs: Vec<LweCiphertext<Vec<u64>>>,
    lut: Vec<PolynomialList<Vec<u64>>>,
    pack_size: usize, // 每个多项式能打包多少张表
}

fn make_iter_setup(ctx: &BenchCtx, n_bits: usize) -> IterSetup {
    let num_inputs = n_bits / ctx.params.message_size(); // 你要求的数量

    // 1) 生成 LWE 输入（不计时）
    // 提示：为了完全隔离计时，可复用一个本地 ERG，这里为了简洁省略
    let lwes = {
        // 更稳妥做法：用你已有的 seeder/ERG；这里给出可替换的占位
        let lwe_sk = ctx.glwe_sk.as_lwe_secret_key();
        let mut boxed_seeder = new_seeder();
        let seeder = boxed_seeder.as_mut();
        let mut enc =
            EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);
        (0..num_inputs)
            .map(|_| {
                let m: u64 = rand::random::<u64>() & ((1u64 << ctx.params.message_size()) - 1);
                allocate_and_encrypt_new_lwe_ciphertext(
                    &lwe_sk,
                    Plaintext(m << (u64::BITS as usize - ctx.params.message_size())),
                    // 按需加入真实噪声：
                    ctx.params.lwe_modular_std_dev(),
                    ctx.params.ciphertext_modulus(),
                    &mut enc,
                )
            })
            .collect()
    };
    // 2) a trival lut, just ues it size
    let plain_lut = vec![0usize; 1 << n_bits];
    let split_plain_lut =
        split_adjusted_lut_by_chunk(&plain_lut, n_bits, ctx.params.extract_size());
    let (lut, pack_size) = generate_lut_from_vecs_auto(
        &split_plain_lut,
        ctx.params.polynomial_size(),
        1 << (u64::BITS as usize - ctx.params.message_size()),
    );

    // 3) 预分配 GGSW 容器（不计时；计时阶段只写入）
    let fourier_ggsw_list = FourierGgswCiphertextList::new(
        vec![
            c64::default();
            ctx.params.extract_size()
                * ctx.params.polynomial_size().to_fourier_polynomial_size().0
                * ctx.params.glwe_dimension().to_glwe_size().0
                * ctx.params.glwe_dimension().to_glwe_size().0
                * ctx.params.cbs_level().0
        ],
        ctx.params.extract_size(),
        ctx.params.glwe_dimension().to_glwe_size(),
        ctx.params.polynomial_size(),
        ctx.params.cbs_base_log(),
        ctx.params.cbs_level(),
    );
    let fourier_ggsw_lists = vec![fourier_ggsw_list; num_inputs];

    // 4) 输出 LWE 数量（按你的打包策略决定）
    let out_len = n_bits / 4; // 示例：与输入数量相等；按需调整
    let lwe_outs = (0..out_len)
        .map(|_| {
            allocate_and_trivially_encrypt_new_lwe_ciphertext(
                ctx.glwe_sk
                    .as_lwe_secret_key()
                    .lwe_dimension()
                    .to_lwe_size(),
                Plaintext(0u64),
                ctx.params.ciphertext_modulus(),
            )
        })
        .collect();

    IterSetup {
        lwes,
        fourier_ggsw_lists,
        lwe_outs,
        lut,
        pack_size,
    }
}

fn bench_lut_sizes(c: &mut Criterion) {
    let ctx = setup_ctx(*SetI); // 你的初始化

    // ---------------- 日志文件（CSV） ----------------
    let target_dir = env::var("CARGO_TARGET_DIR").unwrap_or_else(|_| "target".into());
    let logs_dir = format!("{}/bench_logs", target_dir);
    let _ = create_dir_all(&logs_dir);
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let log_path = format!("{}/lut_combo_{}.csv", logs_dir, ts);
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .unwrap();
    let writer = Arc::new(Mutex::new(BufWriter::new(file)));

    // 写 CSV 表头
    {
        let mut w = writer.lock().unwrap();
        let _ = writeln!(w, "n_bits,threads,avg_cbs_ms,avg_lut_ms,avg_total_ms,iters");
        let _ = w.flush();
    }

    // ---------------- 进度条 ----------------
    let n_vals = [4usize, 8, 12, 16];
    let thread_vals = [1usize, 2, 4];
    let total_cases = (n_vals.len() * thread_vals.len() * SAMPLE_SIZE) as u64;
    let pb = Arc::new(ProgressBar::new(total_cases));
    pb.set_style(
        ProgressStyle::with_template(
            "[{elapsed_precise}] [{bar:40}] {pos}/{len} {msg} (eta {eta})",
        )
        .unwrap()
        .progress_chars("=>-"),
    );

    let mut group = c.benchmark_group("lut_n_to_n_combo");

    for &n_bits in &n_vals {
        for &threads in &thread_vals {
            let writer = writer.clone();

            group.bench_with_input(
                BenchmarkId::new(format!("combo_t{}", threads), n_bits),
                &n_bits,
                |b, &nb| {
                    b.iter_custom(|iters| {
                        // 局部 Rayon 线程池（不计时）
                        let pool = ThreadPoolBuilder::new()
                            .num_threads(threads)
                            .build()
                            .unwrap();

                        let mut sum_total = Duration::ZERO;
                        let mut sum_cbs = Duration::ZERO;
                        let mut sum_lut = Duration::ZERO;

                        for _ in 0..iters {
                            // 不计时：一次迭代的准备（加密若干 LWE、trivial LUT、预分配容器等）
                            let mut prep = make_iter_setup(&ctx, nb);

                            // 计时 CBS
                            let t0 = Instant::now();
                            pool.install(|| {
                                run_cbs_part(&ctx, &mut prep);
                            });
                            let dt_cbs = t0.elapsed();

                            // 计时 LUT
                            let t1 = Instant::now();
                            pool.install(|| {
                                run_lut_part(&ctx, &mut prep, nb);
                            });
                            let dt_lut = t1.elapsed();

                            sum_cbs += dt_cbs;
                            sum_lut += dt_lut;
                            sum_total += dt_cbs + dt_lut;

                            black_box(&prep); // 防优化
                        }

                        // 平均值（毫秒）
                        let iters_f = iters as f64;
                        let avg_cbs_ms = (sum_cbs.as_secs_f64() * 1e3) / iters_f;
                        let avg_lut_ms = (sum_lut.as_secs_f64() * 1e3) / iters_f;
                        let avg_total_ms = (sum_total.as_secs_f64() * 1e3) / iters_f;

                        // 写入日志（CSV）
                        {
                            let mut w = writer.lock().unwrap();
                            let _ = writeln!(
                                w,
                                "{},{},{:.6},{:.6},{:.6},{}",
                                nb, threads, avg_cbs_ms, avg_lut_ms, avg_total_ms, iters
                            );
                            let _ = w.flush();
                        }
                        // 进度条前进一格（每个 n_bits×threads 组合完成一次测量时）
                        pb.set_message(format!("n_bits={n_bits} threads={threads}"));
                        pb.inc(1);
                        // 返回 total 给 Criterion 用于曲线/统计
                        sum_total
                    });
                },
            );
        }
    }

    group.finish();
    pb.finish_with_message(format!("done. log: {}", log_path));
}

fn small_runs() -> Criterion {
    Criterion::default()
        .sample_size(SAMPLE_SIZE) // 改这里
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(100))
        .configure_from_args() // 允许命令行再覆盖
}
criterion_group! {
    name = benches;
    config = small_runs();  // 注意这里要调用 ()
    targets = bench_lut_sizes
}
criterion_main!(benches);
