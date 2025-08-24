use criterion::{black_box, criterion_group, criterion_main, Criterion};
use fhe_processor::{
    operations::{
        manager::{OperationManager, Step},
        operand::ArithmeticOp,
        operation::OperandType,
    },
    utils::instance::SetI,
};
use rand::{thread_rng, Rng};
use std::time::{Duration, Instant};

// ---- 修改为你工程的路径 ----

// ---------------------------

fn is_unary(op: &ArithmeticOp) -> bool {
    matches!(op, ArithmeticOp::NOT | ArithmeticOp::MOVE)
}

fn safe_const_for(op: &ArithmeticOp) -> usize {
    match op {
        ArithmeticOp::Div | ArithmeticOp::Mod => 7, // 非 0
        ArithmeticOp::SL | ArithmeticOp::SR | ArithmeticOp::RL | ArithmeticOp::RR => 3, // 合理移位
        _ => 5,
    }
}

// 构建并配置 manager（位宽=8），根据 op 与操作数类型设定执行计划
fn make_manager(op: ArithmeticOp, operand: OperandType) -> (OperationManager, usize /*out_idx*/) {
    let mut manager = OperationManager::new(*SetI, 10, 8);
    let unary = is_unary(&op);

    match operand {
        OperandType::BothCipher => {
            // 二元：输入 [0,1] -> out=2；一元：输入 [0] -> out=1
            if unary {
                manager.add_operation(op, OperandType::BothCipher, None);
                manager.set_execution_plan(vec![Step::new(0, vec![0], 1)]);
                (manager, 1)
            } else {
                manager.add_operation(op, OperandType::BothCipher, None);
                manager.set_execution_plan(vec![Step::new(0, vec![0, 1], 2)]);
                (manager, 2)
            }
        }
        OperandType::PlainCipher | OperandType::CipherPlain => {
            let k = safe_const_for(&op);
            manager.add_operation(op, operand, Some(k));
            // 一元/二元在执行计划上都只需要一个密文输入 [0]，输出到 1
            manager.set_execution_plan(vec![Step::new(0, vec![0], 1)]);
            (manager, 1)
        }
    }
}

// 只计时 execute()；加载/清理不计时
fn bench_one_combo(c: &mut Criterion, label: &str, op: ArithmeticOp, operand: OperandType) {
    let (mut manager, out_idx) = make_manager(op, operand);

    let mut rng = thread_rng();
    c.bench_function(label, |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                // 8-bit 随机输入
                let mut a: u32 = rng.gen();
                let mut bval: u32 = rng.gen();
                a %= 1 << 8;
                bval %= 1 << 8;

                // 避免非法：除/模非 0；移位量 < 8
                match op {
                    ArithmeticOp::Div | ArithmeticOp::Mod => {
                        if bval == 0 {
                            bval = 7;
                        }
                    }
                    ArithmeticOp::SL | ArithmeticOp::SR | ArithmeticOp::RL | ArithmeticOp::RR => {
                        bval %= 8;
                    }
                    _ => {}
                }

                // —— 加载输入（不计时）——
                match operand {
                    OperandType::BothCipher => {
                        if is_unary(&op) {
                            manager.load_data(a as usize, 0);
                        } else {
                            manager.load_data(a as usize, 0);
                            manager.load_data(bval as usize, 1);
                        }
                    }
                    OperandType::PlainCipher | OperandType::CipherPlain => {
                        // 常量已在 add_operation 中指定；这里只加载密文输入
                        manager.load_data(a as usize, 0);
                    }
                    _ => {}
                }

                // —— 仅计时 execute() ——
                let t0 = Instant::now();
                manager.execute();
                total += t0.elapsed();

                // 读回防优化（不计时）
                black_box(manager.get_data(out_idx));
            }
            total
        });
    });
}

fn benches_all_ops(c: &mut Criterion) {
    use ArithmeticOp::*;
    // 需要覆盖的指令
    let ops: &[ArithmeticOp] = &[
        Add, Sub, Mul, Mulh, Div, Mod, EQ, GT, LT, GTE, LTE, MAX, MIN, RL, RR, SL, SR, OR, AND,
        XOR, NAND, 
    ];

    // 三种 OperandType（PlainCipher 与 CipherPlain 统一逻辑）
    let modes: &[(&'static str, OperandType)] = &[
        ("CC", OperandType::BothCipher),
        ("PC", OperandType::PlainCipher),
        ("CP", OperandType::CipherPlain),
    ];

    for op in ops {
        for (tag, mode) in modes {
            let label = format!("{:?} ({})", op, tag);
            bench_one_combo(c, &label, *op, mode.clone());
        }
    }
}

fn config() -> Criterion {
    Criterion::default()
        .sample_size(20)
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(10))
        .configure_from_args()
}
criterion_group! {
    name = benches;
    config = config();  // 注意这里要调用 ()
    targets = benches_all_ops,
}

criterion_main!(benches);
