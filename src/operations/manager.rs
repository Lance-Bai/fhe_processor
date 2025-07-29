use concrete_fft::c64;
use tfhe::core_crypto::prelude::FourierGgswCiphertextList;




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