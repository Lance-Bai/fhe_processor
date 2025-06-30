use tfhe::core_crypto::prelude::{CastFrom, UnsignedTorus};

fn decode_special_encoded_byte(encoded: u8) -> u8 {
    // 分离高低nibble
    let high_nibble = (encoded >> 4) & 0xF;
    let low_nibble = encoded & 0xF;

    // 高四位
    let h0 = (high_nibble >> 3) & 1;
    let h1 = (high_nibble >> 2) & 1;
    let h2 = (high_nibble >> 1) & 1;
    let h3 = high_nibble & 1;

    let b0 = h0;
    let b1 = h0 ^ h1;
    let b2 = h1 ^ h2;
    let b3 = h2 ^ h3;

    // 低四位
    let l0 = (low_nibble >> 3) & 1;
    let l1 = (low_nibble >> 2) & 1;
    let l2 = (low_nibble >> 1) & 1;
    let l3 = low_nibble & 1;

    let b4 = l0;
    let b5 = l0 ^ l1;
    let b6 = l1 ^ l2;
    let b7 = l2 ^ l3;

    // 组合成原始字节
    (b0 << 7)
        | (b1 << 6)
        | (b2 << 5)
        | (b3 << 4)
        | (b4 << 3)
        | (b5 << 2)
        | (b6 << 1)
        | b7
}

pub fn encode_special_byte(input: u8) -> ([u64; 4], [u64; 4]) {
    // 拆分高四位和低四位
    let high = (input >> 4) & 0xF;
    let low = input & 0xF;

    let mut high_bits = [0u64; 4];
    let mut low_bits = [0u64; 4];

    let mut acc = 0;
    // 高四位，从左到右累积异或
    for i in 0..4 {
        let bit = (high >> (3 - i)) & 1;
        acc ^= bit;
        high_bits[i] = acc as u64;
    }

    acc = 0;
    // 低四位，从左到右累积异或
    for i in 0..4 {
        let bit = (low >> (3 - i)) & 1;
        acc ^= bit;
        low_bits[i] = acc as u64;
    }

    (high_bits, low_bits)
}

// 定义算术运算类型
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ArithmeticOp {
    Add,
    Sub,
    Mul,
    Div,
}

impl ArithmeticOp {
    fn compute(&self, a: u8, b: u8) -> u8 {
        match self {
            ArithmeticOp::Add => a.wrapping_add(b),
            ArithmeticOp::Sub => a.wrapping_sub(b),
            ArithmeticOp::Mul => a.wrapping_mul(b),
            ArithmeticOp::Div => {
                if b == 0 {
                    0 // 定义除零结果为0，可根据需要调整
                } else {
                    a / b
                }
            }
        }
    }

    fn name(&self) -> &'static str {
        match self {
            ArithmeticOp::Add => "addition",
            ArithmeticOp::Sub => "subtraction",
            ArithmeticOp::Mul => "multiplication",
            ArithmeticOp::Div => "division",
        }
    }
}

// 通用算术查找表
pub struct ArithmeticLookupTables<Scalar: UnsignedTorus + CastFrom<u64> + Copy> {
    low_nibble_table: Vec<Scalar>,
    high_nibble_table: Vec<Scalar>,
    operation: ArithmeticOp,
}

impl<Scalar: UnsignedTorus + CastFrom<u64> + Copy> ArithmeticLookupTables<Scalar> {
    pub fn new(operation: ArithmeticOp) -> Self {
        let (low_nibble_table, high_nibble_table) = Self::generate_tables(operation);
        Self {
            low_nibble_table,
            high_nibble_table,
            operation,
        }
    }

    fn generate_tables(operation: ArithmeticOp) -> (Vec<Scalar>, Vec<Scalar>) {
        let table_size = 256 * 256;
        let mut low_nibble_table = vec![Scalar::ZERO; table_size];
        let mut high_nibble_table = vec![Scalar::ZERO; table_size];

        for normal_input in 0u8..=255 {
            for encoded_input in 0u8..=255 {
                let decoded_input = decode_special_encoded_byte(encoded_input);
                let result = operation.compute(normal_input, decoded_input);

                let low_nibble = Scalar::cast_from((result & 0xF) as u64);
                let high_nibble = Scalar::cast_from(((result >> 4) & 0xF) as u64);

                let table_index = (normal_input as usize) * 256 + (encoded_input as usize);

                low_nibble_table[table_index] = low_nibble;
                high_nibble_table[table_index] = high_nibble;
            }
        }

        (low_nibble_table, high_nibble_table)
    }

    pub fn get_operation(&self) -> ArithmeticOp {
        self.operation
    }

    pub fn get_subtable(&self, normal_input: u8) -> ArithmeticSubTable<Scalar> {
        let subtable_start = (normal_input as usize) * 256;
        ArithmeticSubTable {
            low_nibble_data: &self.low_nibble_table[subtable_start..subtable_start + 256],
            high_nibble_data: &self.high_nibble_table[subtable_start..subtable_start + 256],
            normal_input,
            operation: self.operation,
        }
    }

    pub fn lookup(&self, normal_input: u8, encoded_input: u8) -> (Scalar, Scalar) {
        let index = (normal_input as usize) * 256 + (encoded_input as usize);
        (self.low_nibble_table[index], self.high_nibble_table[index])
    }

    pub fn get_low_nibble_table(&self) -> &[Scalar] {
        &self.low_nibble_table
    }

    pub fn get_high_nibble_table(&self) -> &[Scalar] {
        &self.high_nibble_table
    }

    pub fn memory_usage(&self) -> usize {
        (self.low_nibble_table.len() + self.high_nibble_table.len()) * std::mem::size_of::<Scalar>()
    }
}

// 通用算术子表
pub struct ArithmeticSubTable<'a, Scalar: UnsignedTorus + CastFrom<u64> + Copy> {
    low_nibble_data: &'a [Scalar],
    high_nibble_data: &'a [Scalar],
    normal_input: u8,
    operation: ArithmeticOp,
}

impl<'a, Scalar: UnsignedTorus + CastFrom<u64> + Copy> ArithmeticSubTable<'a, Scalar> {
    pub fn lookup(&self, encoded_input: u8) -> (Scalar, Scalar) {
        let index = encoded_input as usize;
        (self.low_nibble_data[index], self.high_nibble_data[index])
    }

    pub fn lookup_low_nibble(&self, encoded_input: u8) -> Scalar {
        self.low_nibble_data[encoded_input as usize]
    }

    pub fn lookup_high_nibble(&self, encoded_input: u8) -> Scalar {
        self.high_nibble_data[encoded_input as usize]
    }

    pub fn lookup_batch(&self, encoded_inputs: &[u8]) -> Vec<(Scalar, Scalar)> {
        encoded_inputs
            .iter()
            .map(|&encoded| self.lookup(encoded))
            .collect()
    }

    pub fn lookup_low_nibble_batch(&self, encoded_inputs: &[u8]) -> Vec<Scalar> {
        encoded_inputs
            .iter()
            .map(|&encoded| self.lookup_low_nibble(encoded))
            .collect()
    }

    pub fn lookup_high_nibble_batch(&self, encoded_inputs: &[u8]) -> Vec<Scalar> {
        encoded_inputs
            .iter()
            .map(|&encoded| self.lookup_high_nibble(encoded))
            .collect()
    }

    pub fn get_normal_input(&self) -> u8 {
        self.normal_input
    }

    pub fn get_operation(&self) -> ArithmeticOp {
        self.operation
    }

    pub fn get_low_nibble_subtable(&self) -> &[Scalar] {
        self.low_nibble_data
    }

    pub fn get_high_nibble_subtable(&self) -> &[Scalar] {
        self.high_nibble_data
    }
}

// 算术查找表管理器
pub struct ArithmeticLookupManager<Scalar: UnsignedTorus + CastFrom<u64> + Copy> {
    tables: std::collections::HashMap<ArithmeticOp, ArithmeticLookupTables<Scalar>>,
}

impl<Scalar: UnsignedTorus + CastFrom<u64> + Copy> ArithmeticLookupManager<Scalar> {
    pub fn new() -> Self {
        Self {
            tables: std::collections::HashMap::new(),
        }
    }

    pub fn add_operation(&mut self, operation: ArithmeticOp) {
        println!("生成{}查找表...", operation.name());
        let tables = ArithmeticLookupTables::<Scalar>::new(operation);
        self.tables.insert(operation, tables);
    }

    pub fn add_operations(&mut self, operations: &[ArithmeticOp]) {
        for &op in operations {
            self.add_operation(op);
        }
    }

    pub fn get_table(&self, operation: ArithmeticOp) -> Option<&ArithmeticLookupTables<Scalar>> {
        self.tables.get(&operation)
    }

    pub fn get_subtable(
        &self,
        operation: ArithmeticOp,
        normal_input: u8,
    ) -> Option<ArithmeticSubTable<Scalar>> {
        self.tables
            .get(&operation)
            .map(|table| table.get_subtable(normal_input))
    }

    pub fn lookup(
        &self,
        operation: ArithmeticOp,
        normal_input: u8,
        encoded_input: u8,
    ) -> Option<(Scalar, Scalar)> {
        self.tables
            .get(&operation)
            .map(|table| table.lookup(normal_input, encoded_input))
    }

    pub fn get_loaded_operations(&self) -> Vec<ArithmeticOp> {
        self.tables.keys().copied().collect()
    }

    pub fn total_memory_usage(&self) -> usize {
        self.tables.values().map(|table| table.memory_usage()).sum()
    }

    pub fn remove_operation(&mut self, operation: ArithmeticOp) -> bool {
        self.tables.remove(&operation).is_some()
    }

    pub fn clear(&mut self) {
        self.tables.clear();
    }
}

impl<Scalar: UnsignedTorus + CastFrom<u64> + Copy> Default for ArithmeticLookupManager<Scalar> {
    fn default() -> Self {
        Self::new()
    }
}

// 测试和演示
fn test_arithmetic_operations() {
    let mut manager = ArithmeticLookupManager::<u64>::new();

    // 添加所有运算
    manager.add_operations(&[
        ArithmeticOp::Add,
        ArithmeticOp::Sub,
        ArithmeticOp::Mul,
        ArithmeticOp::Div,
    ]);

    println!("已加载运算: {:?}", manager.get_loaded_operations());
    println!(
        "总内存使用: {} MB",
        manager.total_memory_usage() / 1024 / 1024
    );

    // 测试用例
    let test_cases = [(100u8, 50u8), (255, 1), (0, 128), (42, 123), (1, 7)];

    for (normal, encoded) in test_cases {
        let decoded = decode_special_encoded_byte(encoded);
        println!(
            "\n测试: normal={}, encoded={:08b}, decoded={}",
            normal, encoded, decoded
        );

        for op in [
            ArithmeticOp::Add,
            ArithmeticOp::Sub,
            ArithmeticOp::Mul,
            ArithmeticOp::Div,
        ] {
            let expected = op.compute(normal, decoded);
            let expected_low = (expected & 0xF) as u64;
            let expected_high = ((expected >> 4) & 0xF) as u64;

            if let Some((result_low, result_high)) = manager.lookup(op, normal, encoded) {
                let match_result = expected_low == result_low && expected_high == result_high;
                println!(
                    "  {}: {} -> 期望=({},{}) 结果=({},{}) 匹配={}",
                    op.name(),
                    expected,
                    expected_low,
                    expected_high,
                    result_low,
                    result_high,
                    match_result
                );
            }
        }
    }
}

fn test_subtable_operations() {
    println!("\n=== 子表操作测试 ===");
    let mut manager = ArithmeticLookupManager::<u64>::new();
    manager.add_operation(ArithmeticOp::Add);

    let normal_input = 77u8;
    if let Some(subtable) = manager.get_subtable(ArithmeticOp::Add, normal_input) {
        println!(
            "选择{}运算，正常输入{}的子表",
            subtable.get_operation().name(),
            normal_input
        );

        let encoded_inputs = [0u8, 15, 240, 255];
        let batch_results = subtable.lookup_batch(&encoded_inputs);

        for (encoded, (low, high)) in encoded_inputs.iter().zip(batch_results.iter()) {
            let decoded = decode_special_encoded_byte(*encoded);
            let expected = ArithmeticOp::Add.compute(normal_input, decoded);
            println!(
                "  编码输入: {}, 解码: {}, 期望: {}, 结果: ({}, {})",
                encoded, decoded, expected, low, high
            );
        }
    }
}

fn benchmark_operations() {
    use std::time::Instant;

    println!("\n=== 性能测试 ===");
    let mut manager = ArithmeticLookupManager::<u64>::new();
    manager.add_operations(&[ArithmeticOp::Add, ArithmeticOp::Mul]);

    let iterations = 1_000_000;

    for op in [ArithmeticOp::Add, ArithmeticOp::Mul] {
        let start = Instant::now();
        let mut sum = 0u64;

        for i in 0..iterations {
            let normal = (i % 256) as u8;
            let encoded = ((i * 17) % 256) as u8;
            if let Some((low, high)) = manager.lookup(op, normal, encoded) {
                sum += low + high;
            }
        }

        let elapsed = start.elapsed();
        println!(
            "{} 查找 {} 次耗时: {:?}, 校验和: {}",
            op.name(),
            iterations,
            elapsed,
            sum
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_operations_correctness() {
        let mut manager = ArithmeticLookupManager::new();
        manager.add_operations(&[
            ArithmeticOp::Add,
            ArithmeticOp::Sub,
            ArithmeticOp::Mul,
            ArithmeticOp::Div,
        ]);

        // 测试所有运算的正确性（抽样测试）
        for normal in (0u8..=255).step_by(17) {
            for encoded in (0u8..=255).step_by(19) {
                let decoded = decode_special_encoded_byte(encoded);

                for op in [
                    ArithmeticOp::Add,
                    ArithmeticOp::Sub,
                    ArithmeticOp::Mul,
                    ArithmeticOp::Div,
                ] {
                    let expected = op.compute(normal, decoded);
                    let expected_low = (expected & 0xF) as u64;
                    let expected_high = ((expected >> 4) & 0xF) as u64;

                    let (result_low, result_high) = manager.lookup(op, normal, encoded).unwrap();
                    assert_eq!(
                        (expected_low, expected_high),
                        (result_low, result_high),
                        "{} 失败: normal={}, encoded={}, decoded={}",
                        op.name(),
                        normal,
                        encoded,
                        decoded
                    );
                }
            }
        }
    }

    #[test]
    fn test_manager_operations() {
        let mut manager = ArithmeticLookupManager::<u64>::new();

        // 测试添加和移除操作
        assert_eq!(manager.get_loaded_operations().len(), 0);

        manager.add_operation(ArithmeticOp::Add);
        assert_eq!(manager.get_loaded_operations().len(), 1);
        assert!(manager.get_table(ArithmeticOp::Add).is_some());

        manager.remove_operation(ArithmeticOp::Add);
        assert_eq!(manager.get_loaded_operations().len(), 0);
        assert!(manager.get_table(ArithmeticOp::Add).is_none());
    }

    #[test]
    fn test_division_by_zero() {
        let tables = ArithmeticLookupTables::<u64>::new(ArithmeticOp::Div);

        // 测试除零情况
        for normal in 0u8..=255 {
            // 找到解码后为0的编码输入
            for encoded in 0u8..=255 {
                let decoded = decode_special_encoded_byte(encoded);
                if decoded == 0 {
                    let (low, high) = tables.lookup(normal, encoded);
                    // 除零结果应该是0
                    assert_eq!(low, 0);
                    assert_eq!(high, 0);
                    break;
                }
            }
        }
    }
    #[test]
    fn main() {
        test_arithmetic_operations();
        // test_subtable_operations();
        // benchmark_operations();
    }
}
