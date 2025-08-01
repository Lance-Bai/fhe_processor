use std::collections::HashMap;

use aligned_vec::ABox;
use concrete_fft::c64;
use refined_tfhe_lhe::AutomorphKey;
use tfhe::{
    boolean::prelude::PolynomialSize,
    core_crypto::{
        prelude::{
            ActivatedRandomGenerator, ComputationBuffers, EncryptionRandomGenerator, Fft, FourierGgswCiphertextList, FourierLweBootstrapKeyOwned, GlweSecretKeyOwned, LweCiphertext, LweKeyswitchKeyOwned, LweSecretKeyOwned, SecretRandomGenerator
        },
        seeders::{new_seeder, Seeder},
    },
};

use crate::{operations::operation::Operation, utils::parms::ProcessorParam};

pub struct Step {
    pub op_index: usize,           // Operation在Vec中的索引
    pub input_indices: Vec<usize>, // 这一操作的输入数据在DataList中的索引
    pub output_index: usize,       // 结果写入DataList哪个位置
}

pub struct OperationManager {
    pub operations: Vec<Operation>,
    pub execution_plan: Vec<Step>,
    pub buffer: ComputationBuffers,        // 计算缓冲区
    pub fft: Fft,                          // FFT实例
    pub boxed_seeder: Box<dyn Seeder>, // 必须存活以保证encryption_generator的正确性
    pub secret_generator: SecretRandomGenerator<ActivatedRandomGenerator>,
    pub encryption_generator: EncryptionRandomGenerator<ActivatedRandomGenerator>,

    pub glwe_sk: GlweSecretKeyOwned<u64>,
    pub lwe_sk_after_ks: LweSecretKeyOwned<u64>,
    pub ksk: LweKeyswitchKeyOwned<u64>,
    pub fourier_bsk: FourierLweBootstrapKeyOwned,
    pub auto_keys: HashMap<usize, AutomorphKey<ABox<[c64]>>>, // 假定你有AutoKeysOwned类型
    pub ss_key: FourierGgswCiphertextList<Vec<c64>>,
}

impl OperationManager {
    pub fn new(param: ProcessorParam<u64>) -> Self {
        let lwe_dimension = param.lwe_dimension();
        let lwe_modular_std_dev = param.lwe_modular_std_dev();
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
        let cbs_base_log = param.cbs_base_log();
        let cbs_level = param.cbs_level();
        let ciphertext_modulus = param.ciphertext_modulus();
        let message_size = param.message_size();
        let extract_size = param.extract_size();
        let glwe_size = glwe_dimension.to_glwe_size();
        let delta = 1 << (u64::BITS as usize - message_size);

        let mut boxed_seeder = new_seeder(); // 你自己的Seeder构造函数
        let seeder = boxed_seeder.as_mut();

        let secret_generator = SecretRandomGenerator::new(seeder.seed());
        let encryption_generator = EncryptionRandomGenerator::new(seeder.seed(), seeder);

        
        Self {
            operations: Vec::new(),
            execution_plan: Vec::new(),
            buffer: ComputationBuffers::new(),
            fft: Fft::new(polynomial_size), // 需要实现这个方法或传入已有的
            boxed_seeder,
            secret_generator,
            encryption_generator,
        }
    }

    pub fn add_operation(&mut self, op: Operation) {
        self.operations.push(op);
    }

    pub fn remove_operation(&mut self, index: usize) {
        self.operations.remove(index);
    }

    /// 设置执行步骤
    pub fn set_execution_plan(&mut self, plan: Vec<Step>) {
        self.execution_plan = plan;
    }

    /// 执行整条流水线
    pub fn execute(
        &self,
        mut data_list: Vec<Vec<LweCiphertext<Vec<u64>>>>, // 你要自己定义MyData,如密文数组或其它
        fft: &Fft,
        buffer: &mut ComputationBuffers,
    ) -> Vec<Vec<LweCiphertext<Vec<u64>>>> {
        // for step in &self.execution_plan {
        //     let op = &self.operations[step.op_index];
        //     // 假定都是lwe密文为例，按实际类型修改
        //     let input_datas: Vec<&Vec<LweCiphertext<Vec<u64>>>> =
        //         step.input_indices.iter().map(|&i| data_list[i]).collect();

        //     // 你需要根据实际op接口做参数提取
        //     let (input0, input1) = (/* ... */); // 解包input_datas

        //     // 假设op.vertical_packing_multi_lookup(&mut out, in, fft, buffer)
        //     let mut output = data_list[step.output_index]; // 需要实现Default
        //     op.vertical_packing_multi_lookup(
        //         &mut output, /* 其它参数如input0, input1, fft, buffer */
        //     );

        //     data_list[step.output_index] = Some(output);
        // }
        // data_list
    }
}

pub fn concat_ggsw_lists(
    lists: Vec<FourierGgswCiphertextList<Vec<c64>>>,
) -> FourierGgswCiphertextList<Vec<c64>> {
    assert!(!lists.is_empty(), "GGSW list不能为空");

    let glwe_size = lists[0].glwe_size();
    let decomposition_level_count = lists[0].decomposition_level_count();
    let decomposition_base_log = lists[0].decomposition_base_log();
    let poly_size = lists[0].polynomial_size();

    let mut all_data = Vec::new();
    let mut total_count = 0;
    for list in lists {
        total_count += list.count();
        all_data.extend_from_slice(&list.data()); // 此处 data() move 掉 list
    }

    FourierGgswCiphertextList::new(
        all_data,
        total_count,
        glwe_size,
        poly_size,
        decomposition_base_log,
        decomposition_level_count,
    )
}
