#include "instr.h"
#include "instri.h"
#include "tables.h"
#include "bootstrapping.h"
#include <stdlib.h>
#include <math.h>

// This file implement some 16-bit precision operations.

void ADD_16(vector<LweSample*> &result,
	    vector<LweSample*> &a,
	    vector<LweSample*> &b,
	    TFheGateBootstrappingSecretKeySet* key,
	    BaseBKeySwitchKey* ks_key){
  vector<LweSample*> lsb, msb, carry, tmp_msb, tmp_lsb, result_bis, overhead, tmp, w, r;
  lsb.push_back(new_LweSample(key->lwe_key->params));
  lsb.push_back(new_LweSample(key->lwe_key->params));
  lsb.push_back(new_LweSample(key->lwe_key->params));
  msb.push_back(new_LweSample(key->lwe_key->params));
  msb.push_back(new_LweSample(key->lwe_key->params));
  msb.push_back(new_LweSample(key->lwe_key->params));
  tmp_msb.push_back(new_LweSample(key->lwe_key->params));
  tmp_msb.push_back(new_LweSample(key->lwe_key->params));
  tmp_lsb.push_back(new_LweSample(key->lwe_key->params));
  tmp_lsb.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  result_bis.push_back(new_LweSample(key->lwe_key->params));
  result_bis.push_back(new_LweSample(key->lwe_key->params));
  overhead.push_back(new_LweSample(key->lwe_key->params));
  overhead.push_back(new_LweSample(key->lwe_key->params));
  overhead.push_back(new_LweSample(key->lwe_key->params));
  carry.push_back(new_LweSample(key->lwe_key->params));
  carry.push_back(new_LweSample(key->lwe_key->params));
  carry.push_back(new_LweSample(key->lwe_key->params));
  w.push_back(new_LweSample(key->lwe_key->params));
  w.push_back(new_LweSample(key->lwe_key->params));
  r.push_back(new_LweSample(key->lwe_key->params));
  r.push_back(new_LweSample(key->lwe_key->params));

  lweCopy(lsb[0], a[3], key->lwe_key->params);
  lweCopy(lsb[1], b[3], key->lwe_key->params);
  lweCopy(lsb[2], b[3], key->lwe_key->params);
  lweCopy(msb[0], a[2], key->lwe_key->params);
  lweCopy(msb[1], b[2], key->lwe_key->params);
  lweCopy(msb[2], b[2], key->lwe_key->params);
  //sum of lsn
  word8* tab_dec[256]={tab_add_msb, tab_add_lsb};
  deref_boot_opti(tmp_lsb, key, lsb, ks_key, tab_dec);
  lweCopy(carry[0], tmp_lsb[0], key->lwe_key->params);
  lweCopy(result_bis[1], tmp_lsb[1], key->lwe_key->params);
  //sum of msn
  deref_boot_opti(tmp_msb, key, msb, ks_key, tab_dec);
  lweCopy(carry[1], tmp_msb[1], key->lwe_key->params);
  lweCopy(carry[2], tmp_msb[1], key->lwe_key->params);
  deref_boot_opti(r, key, carry, ks_key, tab_dec);
  lweCopy(result_bis[0], r[1], key->lwe_key->params);
  lweCopy(r[1], tmp_msb[0], key->lwe_key->params);
  deref_boot_single(overhead, key, r, ks_key, tab_add_dec_msb); 

  lweCopy(lsb[0], a[1], key->lwe_key->params);
  lweCopy(lsb[1], b[1], key->lwe_key->params);
  lweCopy(lsb[2], b[1], key->lwe_key->params); 
  lweCopy(msb[0], a[0], key->lwe_key->params);
  lweCopy(msb[1], b[0], key->lwe_key->params); 
  lweCopy(msb[2], a[0], key->lwe_key->params);

  deref_boot_opti(tmp, key, lsb, ks_key, tab_dec); 
  lweCopy(carry[0], tmp[0], key->lwe_key->params);
  lweCopy(overhead[1], tmp[1], key->lwe_key->params);
  lweCopy(overhead[2], tmp[1], key->lwe_key->params);
  deref_boot_opti(tmp, key, overhead, ks_key, tab_dec);
  lweCopy(result[1], tmp[1], key->lwe_key->params);

  deref_boot_single(tmp, key, msb, ks_key, tab_add_lsb);
  lweCopy(carry[1], tmp[0], key->lwe_key->params);
  deref_boot_single(tmp_msb, key, carry, ks_key, tab_add_lsb);
  lweCopy(result[0], tmp_msb[0], key->lwe_key->params);
  lweCopy(result[2], result_bis[0], key->lwe_key->params);
  lweCopy(result[3], result_bis[1], key->lwe_key->params);
}

void MULi_16(vector<LweSample*> &result,
	     vector<LweSample*> &a,
	     float b,
	     TFheGateBootstrappingSecretKeySet* key,
	     BaseBKeySwitchKey* ks_key){
  vector<LweSample*> tmp, tmp1, tmp23, tmp45,tmp67, ai ;
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp1.push_back(new_LweSample(key->lwe_key->params));
  tmp1.push_back(new_LweSample(key->lwe_key->params));
  tmp23.push_back(new_LweSample(key->lwe_key->params));
  tmp23.push_back(new_LweSample(key->lwe_key->params));
  tmp23.push_back(new_LweSample(key->lwe_key->params));
  tmp23.push_back(new_LweSample(key->lwe_key->params));
  tmp45.push_back(new_LweSample(key->lwe_key->params));
  tmp45.push_back(new_LweSample(key->lwe_key->params));
  tmp45.push_back(new_LweSample(key->lwe_key->params));
  tmp45.push_back(new_LweSample(key->lwe_key->params));
  tmp67.push_back(new_LweSample(key->lwe_key->params));
  tmp67.push_back(new_LweSample(key->lwe_key->params));
  tmp67.push_back(new_LweSample(key->lwe_key->params));
  tmp67.push_back(new_LweSample(key->lwe_key->params));

  float f, g, d;
  // we want to compute a*b = (k,l)*(i,d)
  // that is to say k*i + k*0.d + 0.l*i + 0.l*0.d 
  word8 bi = floor(b);
  ai.push_back(new_LweSample(key->lwe_key->params));
  ai.push_back(new_LweSample(key->lwe_key->params));
  lweCopy(ai[0], a[0], key->lwe_key->params);
  lweCopy(ai[1], a[1], key->lwe_key->params);
  MULi(tmp1, ai, bi, key, ks_key);
  word8 tab_msb[256]={0};
  word8 tab_lsb[256]={0};
  word8 tab_msb_dec[256]={0};
  word8 tab_lsb_dec[256]={0};
  // let's compute k*0.d
  for(int i=0; i<256; i++){
    d = b-bi;
    f = i * d;
    word8 j = (word8)floor(f);
    g = floor((f-j)*256);
    tab_msb[i]=j/16;
    tab_lsb[i]=j%16;
    tab_msb_dec[i]=(word8)g/16;
    tab_lsb_dec[i]=(word8)g%16;
  }
  word8 * tab[256]={tab_msb, tab_lsb, tab_msb_dec, tab_lsb_dec};
  lweCopy(tmp[0], a[1], key->lwe_key->params);
  lweCopy(tmp[1], a[0], key->lwe_key->params);
  lweCopy(tmp[2], a[0], key->lwe_key->params);
  lweCopy(tmp[3], a[0], key->lwe_key->params);
  lweCopy(tmp[4], a[0], key->lwe_key->params);
  deref_boot_opti(tmp23, key, tmp, ks_key, tab);
  // let's compute 0.l*i
  for(float i=0; i<256; i++){
    d = i/256;
    f = bi * d;
    word8 j = (word8)floor(f);
    g = floor((f-j)*256);
    tab_msb[(int)i]=j/16;
    tab_lsb[(int)i]=j%16;
    tab_msb_dec[(int)i]=(word8)g/16;
    tab_lsb_dec[(int)i]=(word8)g%16;
  }
  //word8 * tab3[256]={tab_msb, tab_lsb};
  //word8 * tab4[256]={tab_msb_dec, tab_lsb_dec};
  word8 * tab1[256]={tab_msb, tab_lsb, tab_msb_dec, tab_lsb_dec};
  lweCopy(tmp[0], a[3], key->lwe_key->params);
  lweCopy(tmp[1], a[2], key->lwe_key->params);
  lweCopy(tmp[2], a[2], key->lwe_key->params);
  lweCopy(tmp[3], a[2], key->lwe_key->params);
  lweCopy(tmp[4], a[2], key->lwe_key->params);
  deref_boot_opti(tmp45, key, tmp, ks_key, tab1);
  // let's compute 0.l*0.d
  float n = b-bi;
  for(float i=0; i<256; i++){ 
    d = i/256;
    f = n * d;
    word8 j = (word8)floor(f);
    g = (f-j)*256;
    tab_msb[(int)i]=j/16;
    tab_lsb[(int)i]=j%16;
    tab_msb_dec[(int)i]=(word8)g/16;
    tab_lsb_dec[(int)i]=(word8)g%16;
  }
  //word8 * tab5[256]={tab_msb, tab_lsb};
  //word8 * tab6[256]={tab_msb_dec, tab_lsb_dec};  
  word8 * tab2[256]={tab_msb, tab_lsb, tab_msb_dec, tab_lsb_dec};
  deref_boot_opti(tmp67, key, tmp, ks_key, tab2);
  // we compute the additions
  lweCopy(ai[0], tmp23[0], key->lwe_key->params);
  lweCopy(ai[1], tmp23[1], key->lwe_key->params);
  ADD(tmp1, tmp1, ai, key, ks_key);
  tmp.pop_back();
  lweCopy(tmp[0], tmp1[0], key->lwe_key->params);
  lweCopy(tmp[1], tmp1[1], key->lwe_key->params);
  lweCopy(tmp[2], tmp23[2], key->lwe_key->params);
  lweCopy(tmp[3], tmp23[3], key->lwe_key->params);
  ADD_16(result, tmp45, tmp, key, ks_key);
  ADD_16(result, tmp67, result, key, ks_key);
 }


void sigmoid(vector<LweSample*> &result,
	     vector<LweSample*> &result_dec,
	     vector<LweSample*> &a,
	     vector<LweSample*> &b_dec,
	     TFheGateBootstrappingSecretKeySet* key,
	     BaseBKeySwitchKey* ks_key){
  double alpha = key->lwe_key->params->alpha_min;
  vector<LweSample*> tmp_bool, z, b;
  tmp_bool.push_back(new_LweSample(key->lwe_key->params));
  tmp_bool.push_back(new_LweSample(key->lwe_key->params));
  z.push_back(new_LweSample(key->lwe_key->params));
  z.push_back(new_LweSample(key->lwe_key->params));
  lweSymEncrypt(result[1], modSwitchToTorus32(0, 32), alpha, key->lwe_key);
  lweSymEncrypt(result_dec[0], modSwitchToTorus32(0, 32), alpha, key->lwe_key);
  lweSymEncrypt(result_dec[1], modSwitchToTorus32(0, 32), alpha, key->lwe_key);
  word8 *tab[256]={tab_sigmoid_minus6_msb, tab_sigmoid_minus6_lsb};

  b.push_back(new_LweSample(key->lwe_key->params));
  b.push_back(new_LweSample(key->lwe_key->params));
  b.push_back(new_LweSample(key->lwe_key->params));
  lweCopy(b[0], b_dec[1], key->lwe_key->params);
  lweCopy(b[1], b_dec[0], key->lwe_key->params);
  lweCopy(b[2], b_dec[0], key->lwe_key->params);
  
  // ]-128, -6]
  deref_boot_single(tmp_bool, key, a, ks_key, tab_inf_eq_minus6);
  deref_boot_opti(z, key, b, ks_key, tab);
  MULB(z, z, tmp_bool[0], key, ks_key);
  ADDZ(result_dec, result_dec, z, key, ks_key);
  
  // ]-6, -5]
  EQi(tmp_bool , a, 251, key, ks_key);
  word8 *tab1[256]={tab_sigmoid_minus5_msb, tab_sigmoid_minus5_lsb};
  deref_boot_opti(z, key, b, ks_key, tab1);
  MULB(z, z, tmp_bool[1], key, ks_key);
  ADDZ(result_dec, result_dec, z, key, ks_key);
  
  // ]-5, -4]
  EQi(tmp_bool , a, 252, key, ks_key);
  word8 *tab2[256]={tab_sigmoid_minus4_msb, tab_sigmoid_minus4_lsb};
  deref_boot_opti(z, key, b, ks_key, tab2);
  MULB(z, z, tmp_bool[1], key, ks_key);
  ADDZ(result_dec, result_dec, z, key, ks_key);

  // ]-4, -3]
  EQi(tmp_bool , a, 253, key, ks_key);
  word8 *tab3[256]={tab_sigmoid_minus3_msb, tab_sigmoid_minus3_lsb};
  deref_boot_opti(z, key, b, ks_key, tab3);
  MULB(z, z, tmp_bool[1], key, ks_key);
  ADDZ(result_dec, result_dec, z, key, ks_key);

  // ]-3, -2]
  EQi(tmp_bool , a, 254, key, ks_key);
  word8 *tab4[256]={tab_sigmoid_minus2_msb, tab_sigmoid_minus2_lsb};
  deref_boot_opti(z, key, b, ks_key, tab4);
  MULB(z, z, tmp_bool[1], key, ks_key);
  ADDZ(result_dec, result_dec, z, key, ks_key);

   // ]-2, -1]
  EQi(tmp_bool , a, 255, key, ks_key);
  word8 *tab5[256]={tab_sigmoid_minus1_msb, tab_sigmoid_minus1_lsb};
  deref_boot_opti(z, key, b, ks_key, tab5);
  MULB(z, z, tmp_bool[1], key, ks_key);
  ADDZ(result_dec, result_dec, z, key, ks_key);

  // ]-1, 0]
  TZR(tmp_bool , a, key, ks_key);
  word8 *tab6[256]={tab_sigmoid_0_msb, tab_sigmoid_0_lsb};
  deref_boot_opti(z, key, b, ks_key, tab6);
  MULB(z, z, tmp_bool[1], key, ks_key);
  ADDZ(result_dec, result_dec, z, key, ks_key);

  // ]0, 1]
  EQi(tmp_bool , a, 1, key, ks_key);
  word8 *tab7[256]={tab_sigmoid_1_msb, tab_sigmoid_1_lsb};
  deref_boot_opti(z, key, b, ks_key, tab7);
  MULB(z, z, tmp_bool[1], key, ks_key);
  ADDZ(result_dec, result_dec, z, key, ks_key);

  // ]1, 2]
  EQi(tmp_bool , a, 2, key, ks_key);
  word8 *tab8[256]={tab_sigmoid_2_msb, tab_sigmoid_2_lsb};
  deref_boot_opti(z, key, b, ks_key, tab8);
  MULB(z, z, tmp_bool[1], key, ks_key);
  ADDZ(result_dec, result_dec, z, key, ks_key);

  // ]2, 3]
  EQi(tmp_bool , a, 3, key, ks_key);
  word8 *tab9[256]={tab_sigmoid_3_msb, tab_sigmoid_3_lsb};
  deref_boot_opti(z, key, b, ks_key, tab9);
  MULB(z, z, tmp_bool[1], key, ks_key);
  ADDZ(result_dec, result_dec, z, key, ks_key);

  // ]3, 4]
  EQi(tmp_bool , a, 4, key, ks_key);
  word8 *tab10[256]={tab_sigmoid_4_msb, tab_sigmoid_4_lsb};
  deref_boot_opti(z, key, b, ks_key, tab10);
  MULB(z, z, tmp_bool[1], key, ks_key);
  ADDZ(result_dec, result_dec, z, key, ks_key);
  
  // ]4, 5]
  EQi(tmp_bool , a, 5, key, ks_key);
  word8 *tab11[256]={tab_sigmoid_5_msb, tab_sigmoid_5_lsb};
  deref_boot_opti(z, key, b, ks_key, tab11);
  MULB(z, z, tmp_bool[1], key, ks_key);
  ADDZ(result_dec, result_dec, z, key, ks_key);
  
  // ]5, 127]
  deref_boot_single(result, key, a, ks_key, tab_sup_eq_6);
  lweCopy(result[1], result[0], key->lwe_key->params);
  lweSymEncrypt(result[0], modSwitchToTorus32(0, 32), alpha, key->lwe_key);
}


void heaviside(vector<LweSample*> &result,
	       vector<LweSample*> &result_dec,
	       vector<LweSample*> &a,
	       vector<LweSample*> &b,
	       TFheGateBootstrappingSecretKeySet* key,
	       BaseBKeySwitchKey* ks_key){
  vector<LweSample*> tmp, t_zero, t_zero_dec;
  double alpha = key->lwe_key->params->alpha_min;
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  t_zero.push_back(new_LweSample(key->lwe_key->params));
  t_zero.push_back(new_LweSample(key->lwe_key->params));
  t_zero_dec.push_back(new_LweSample(key->lwe_key->params));
  t_zero_dec.push_back(new_LweSample(key->lwe_key->params));

  // if a<0, we return 0
  // if a==0 and b==0, we return 0.5
  
  TZR(t_zero, a, key, ks_key); // a==0
  TZR(t_zero_dec, b, key, ks_key); // b==0
  AND(tmp, t_zero, t_zero_dec, key, ks_key); // a==0 and b==0
  word8 tab[16]= {0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  deref_simple_boot(result_dec, key, tmp,  ks_key, 1, 0, tab);
  lweSymEncrypt(result_dec[1], modSwitchToTorus32(0, 32), alpha, key->lwe_key);

  // if a>=0 we return 1
  GTEi(t_zero, a, 0, key, ks_key);
  GTi(t_zero_dec, b, 0, key, ks_key);
  AND(tmp, t_zero, t_zero_dec, key, ks_key); // a>=0 et b>0
  lweCopy(result[1], tmp[1], key->lwe_key->params);
  lweSymEncrypt(result[0], modSwitchToTorus32(0, 32), alpha, key->lwe_key);
}
