use std::time::Duration;

use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use fhe_processor::{
    operations::{
        manager::{OperationManager, Step},
        operand::ArithmeticOp,
        operation::OperandType::*,
    },
    utils::instance::SetI,
};

fn setup_manager() -> OperationManager {
    let mut manager = OperationManager::new(*SetI, 10, 16);
    manager.add_operation(ArithmeticOp::Add, PlainCipher, Some(2));
    manager.add_operation(ArithmeticOp::Add, BothCipher, None);

    manager.set_execution_plan(vec![Step::new(0, vec![0], 0)]);

    manager
}

/// 仅测一次“加载两条数据 -> 执行 -> 读回结果”的开销，
/// manager 在每次迭代前重新构造（把构造成本也算在内）
fn bench_full_cycle_with_setup(c: &mut Criterion) {
    c.bench_function("manager full cycle (includes setup)", |b| {
        let mut i = 0usize;
        b.iter_batched(
            || setup_manager(), // 每次迭代前新建 manager
            |mut manager| {
                // 被测代码
                let ii = i;
                i = i.wrapping_add(1);
                manager.load_data(ii, 0);
                
                manager.execute();
                let result = manager.get_data(0);
                black_box(result); // 避免被优化掉
            },
            BatchSize::SmallInput,
        );
    });
}

fn small_runs() -> Criterion {
    Criterion::default()
        .sample_size(10) // 改这里
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(60))
        .configure_from_args() // 允许命令行再覆盖
}
criterion_group! {
    name = benches;
    config = small_runs();  // 注意这里要调用 ()
    targets = bench_full_cycle_with_setup, 
}
criterion_main!(benches);
