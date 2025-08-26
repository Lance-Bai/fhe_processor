#ifndef H_TABLES
#define H_TABLES

#include <stdio.h>
#include <tfhe.h>
#include <tfhe_io.h>
#include <tfhe_garbage_collector.h>

#include "base_b_keyswitchkey.h"
#include "base_b_keyswitch.h"
#include "tlwe-functions-extra.h"
#include "tlwekeyswitch.h"

using std::vector;
typedef unsigned char word8;


extern word8 tab_add_msb[256];
extern word8 tab_add_lsb[256];
extern word8 tab_mul_msb[256];
extern word8 tab_mul_lsb[256];
extern word8 tab_min[256];
extern word8 tab_max[256];
extern word8 tab_inf[256];
extern word8 tab_sup[256];
extern word8 tab_eq[256];
extern word8 tab_sub_msb[256];
extern word8 tab_sub_lsb[256];
extern word8 tab_xor[256];
extern word8 tab_and[256];
extern word8 tab_or[256];
extern word8 tab_shift_left_msb[256];
extern word8 tab_shift_left_lsb[256];
extern word8 tab_shift_right_msb[256];
extern word8 tab_shift_right_lsb[256];
extern word8 tab_div_msb_1[256];
extern word8 tab_div_msb_2[256];
extern word8 tab_div_lsb[256];
extern word8 tab_mod_msb[256];
extern word8 tab_mod_lsb[256];
extern word8 tab_eq[256];
extern word8 tab_inf_eq[256];
extern word8 tab_sup_eq[256];
extern word8 tab_neg_msb[256];
extern word8 tab_neg_lsb[256];
extern word8 tab_div_dec_msb_1[256];
extern word8 tab_div_dec_msb_2[256];
extern word8 tab_div_dec_lsb_1[256];
extern word8 tab_div_dec_lsb_2[256];
extern word8 tab_abs_msb[256];
extern word8 tab_abs_lsb[256];
extern word8 tab_mul_spe[256];

extern word8 tab_sigmoid_minus6_msb[256];
extern word8 tab_sigmoid_minus5_msb[256];
extern word8 tab_sigmoid_minus4_msb[256];
extern word8 tab_sigmoid_minus3_msb[256];
extern word8 tab_sigmoid_minus2_msb[256];
extern word8 tab_sigmoid_minus1_msb[256];
extern word8 tab_sigmoid_0_msb[256];
extern word8 tab_sigmoid_1_msb[256];
extern word8 tab_sigmoid_2_msb[256];
extern word8 tab_sigmoid_3_msb[256];
extern word8 tab_sigmoid_4_msb[256];
extern word8 tab_sigmoid_5_msb[256];
extern word8 tab_sigmoid_minus6_lsb[256];
extern word8 tab_sigmoid_minus5_lsb[256];
extern word8 tab_sigmoid_minus4_lsb[256];
extern word8 tab_sigmoid_minus3_lsb[256];
extern word8 tab_sigmoid_minus2_lsb[256];
extern word8 tab_sigmoid_minus1_lsb[256];
extern word8 tab_sigmoid_0_lsb[256];
extern word8 tab_sigmoid_1_lsb[256];
extern word8 tab_sigmoid_2_lsb[256];
extern word8 tab_sigmoid_3_lsb[256];
extern word8 tab_sigmoid_4_lsb[256];
extern word8 tab_sigmoid_5_lsb[256];
extern word8 tab_inf_eq_minus6[256];
extern word8 tab_sup_eq_6[256];

extern word8 and_8[16];
extern word8 and_4[16];
extern word8 and_2[16];
extern word8 and_1[16];

extern word8 tab_add_dec_msb[256];

void testv_b16(TorusPolynomial *testv, int32_t N, uint8_t idx, word8 tab[256]);
void testv_vi_b16(IntPolynomial *testv, int32_t N, uint8_t idx, word8 tab[256]);
void testv_vi_b16_2(IntPolynomial *testv, int32_t N, word8 tab[16]);
void test_v0(TorusPolynomial *testv, int32_t N);
void testv_and(TorusPolynomial *testv, int32_t N, word8 tab[16]);
void testv_vi_and(IntPolynomial *testv, int32_t N, uint8_t i);
void tLweMulByXai(TLweSample *result, int32_t ai, const TLweSample *bk, const TLweParams *params);
void ks_batching(int i, uint8_t B, vector <LweSample*> &resLwe, vector<TLweSample*> &resTLwe, const TLweKey * k_out , BaseBKeySwitchKey* ks_key);




#endif
