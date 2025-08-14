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
// 按你的实际包名导入
// 比如 crate 名叫 mycrate：

fn setup_manager() -> OperationManager {
    // 和原测试里的初始化一致
    let mut manager = OperationManager::new(*SetI, 10, 16);
    manager.add_operation(ArithmeticOp::Add, PlainCipher, Some(2));
    // manager.add_operation(ArithmeticOp::Mul, BothCipher, None);
    // manager.set_execution_plan(vec![Step::new(0, vec![0], 0), Step::new(1, vec![0, 1], 2)]);
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
                // manager.load_data(ii + 3, 1);
                manager.execute();
                let result = manager.get_data(0);
                black_box(result); // 避免被优化掉
            },
            BatchSize::SmallInput,
        );
    });
}

/// 只测执行路径（manager 只构造一次，不把构造成本算进去）
// fn bench_execute_only(c: &mut Criterion) {
//     c.bench_function("manager execute only (reuse manager)", |b| {
//         // manager 仅构造一次
//         b.iter_batched_ref(
//             || setup_manager(),
//             |manager| {
//                 // 用一个本地计数生成不同输入
//                 static mut I: usize = 0;
//                 let ii = unsafe {
//                     let v = I;
//                     I = I.wrapping_add(1);
//                     v
//                 };

//                 manager.load_data(ii, 0);
//                 manager.load_data(ii + 3, 1);
//                 manager.execute();
//                 let result = manager.get_data(2);
//                 black_box(result);
//             },
//             BatchSize::SmallInput,
//         );
//     });
// }
fn small_runs() -> Criterion {
    Criterion::default()
        .sample_size(10) // 改这里
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(100))
        .configure_from_args() // 允许命令行再覆盖
}
criterion_group! {
    name = benches;
    config = small_runs();  // 注意这里要调用 ()
    targets = bench_full_cycle_with_setup, 
}
criterion_main!(benches);
