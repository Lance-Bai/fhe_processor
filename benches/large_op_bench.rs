// benches/manager_execute.rs
use std::time::{Duration, Instant};
use fhe_processor::{operations::{manager::{OperationManager, Step}, operand::ArithmeticOp, operation::OperandType}, utils::instance::{SetI, SetI_large, ZeroNoiseTestII}};
use rand::Rng;
use criterion::{criterion_group, criterion_main, Criterion, black_box};


use tfhe::core_crypto::prelude::CastInto; // 如果你项目里有自定义 CastInto，用你的即可

const DATA_LEN:usize=32;
/// 只测 execute()：LT，(cipher, cipher)
fn bench_manager_execute_lt_cc(c: &mut Criterion) {
    // 与原测试保持一致
    let size = 2_usize;

    // 预先完成一次性初始化
    let mut manager = OperationManager::new(*SetI_large, size + 1, DATA_LEN);
    manager.add_operation(ArithmeticOp::LT, OperandType::BothCipher, None);
    manager.set_execution_plan(vec![Step::new(0, vec![0, 1], size)]);

    c.bench_function("execute_only: LT (cipher,cipher) -bit", |b| {
        b.iter_custom(|iters| {
            let mut rng = rand::thread_rng();
            let mut total = Duration::ZERO;

            for _ in 0..iters {
                // —— 准备阶段（不计时）——
                let mut a: u32 = rng.gen();
                let mut b: u32 = rng.gen();
                a %= 65_536;
                b %= 65_536;

                manager.load_data(a.cast_into(), 0);
                manager.load_data(b.cast_into(), 1);

                // —— 仅计时 execute() —— 
                let start = Instant::now();
                manager.execute();
                let end = Instant::now();
                total += end - start;

                // 防止编译器过度优化（不计时）
                let _ = black_box(manager.get_data(size));
            }

            total
        });
    });
}

/// 只测 execute()：GT，(cipher, plain)
fn bench_manager_execute_gt_cp(c: &mut Criterion) {
    // 与原测试保持一致
    let size = 1_usize;
    let b_plain = 500_usize;

    // 预先完成一次性初始化
    let mut manager = OperationManager::new(*SetI, size + 1, 32);
    manager.add_operation(ArithmeticOp::GT, OperandType::CipherPlain, Some(b_plain));
    manager.set_execution_plan(vec![Step::new(0, vec![0], size)]);

    c.bench_function("execute_only: GT (cipher,plain=500) 16-bit", |b| {
        b.iter_custom(|iters| {
            let mut rng = rand::thread_rng();
            let mut total = Duration::ZERO;

            for _ in 0..iters {
                // —— 准备阶段（不计时）——
                let mut a: u32 = rng.gen();
                a %= 65_536;

                manager.load_data(a.cast_into(), 0);

                // —— 仅计时 execute() —— 
                let start = Instant::now();
                manager.execute();
                let end = Instant::now();
                total += end - start;

                // 防止编译器过度优化（不计时）
                let _ = black_box(manager.get_data(size));
            }

            total
        });
    });
}

criterion_group!(
    name = manager_execute;
    config = {
        // 如需与原 sample_size 类似的粒度，可在此调整
        Criterion::default()
            .sample_size(20)         // 可按需调大/调小
            .measurement_time(std::time::Duration::from_secs(5))
    };
    targets =
        bench_manager_execute_lt_cc,
        // bench_manager_execute_gt_cp
);
criterion_main!(manager_execute);
