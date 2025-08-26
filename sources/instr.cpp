#include "instr.h"
#include "instri.h"
#include "tables.h"
#include "bootstrapping.h"
#include <stdlib.h>
#include <math.h>

// This file implements the multivariate instructions of the set in alphabetical order.


void ADD(vector<LweSample*> &result,
	 vector<LweSample*> &a,
	 vector<LweSample*> &b,
	 TFheGateBootstrappingSecretKeySet* key,
	 BaseBKeySwitchKey* ks_key){
  vector<LweSample*> lsn, msn, carry, tmp;
  lsn.push_back(new_LweSample(key->lwe_key->params));
  lsn.push_back(new_LweSample(key->lwe_key->params));
  lsn.push_back(new_LweSample(key->lwe_key->params));
  msn.push_back(new_LweSample(key->lwe_key->params));
  msn.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  carry.push_back(new_LweSample(key->lwe_key->params));
  carry.push_back(new_LweSample(key->lwe_key->params));
  lweCopy(lsn[0], a[1], key->lwe_key->params);
  lweCopy(lsn[1], b[1], key->lwe_key->params);
  lweCopy(lsn[2], b[1], key->lwe_key->params);
  lweCopy(msn[0], a[0], key->lwe_key->params);
  lweCopy(msn[1], b[0], key->lwe_key->params);
  //msn sum
  deref_boot_single(tmp, key, msn, ks_key, tab_add_lsb);
  //lsn and carry
  word8 *tab[256]={tab_add_lsb, tab_add_msb};
  deref_boot_opti(carry, key, lsn, ks_key, tab);

  lweCopy(tmp[1], carry[1], key->lwe_key->params);
  deref_boot_single(result, key, tmp, ks_key, tab_add_lsb);
  lweCopy(result[1], carry[0], key->lwe_key->params);
}


void ADDZ(vector<LweSample*> &result,
	  vector<LweSample*> &a,
	  vector<LweSample*> &b,
	  TFheGateBootstrappingSecretKeySet* key,
	  BaseBKeySwitchKey* ks_key){
vector<LweSample*> lsb, msb, tmp;
  lsb.push_back(new_LweSample(key->lwe_key->params));
  lsb.push_back(new_LweSample(key->lwe_key->params));
  msb.push_back(new_LweSample(key->lwe_key->params));
  msb.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  lweCopy(lsb[0], a[1], key->lwe_key->params);
  lweCopy(lsb[1], b[1], key->lwe_key->params);
  lweCopy(msb[0], a[0], key->lwe_key->params);
  lweCopy(msb[1], b[0], key->lwe_key->params);
  deref_boot_single(tmp, key, lsb, ks_key, tab_add_lsb);
  deref_boot_single(result, key, msb, ks_key, tab_add_lsb);
  lweCopy(result[1], tmp[0], key->lwe_key->params);
}


void AND(vector <LweSample*> &result,
	 vector <LweSample*> &v1,
	 vector <LweSample*> &v2,
	 TFheGateBootstrappingSecretKeySet* key,
	 BaseBKeySwitchKey* ks_key) {
  vector <LweSample*> d0;
  vector <LweSample*> d1;
  vector <LweSample*> res (1);
  d0.push_back(new_LweSample(key->lwe_key->params));
  d0.push_back(new_LweSample(key->lwe_key->params));
  d1.push_back(new_LweSample(key->lwe_key->params));
  d1.push_back(new_LweSample(key->lwe_key->params));
  lweCopy(d0[0], v1[0], key->lwe_key->params);
  lweCopy(d0[1], v2[0], key->lwe_key->params);
  lweCopy(d1[0], v1[1], key->lwe_key->params);
  lweCopy(d1[1], v2[1], key->lwe_key->params);
  deref_boot_single(result, key, d0, ks_key, tab_and);
  res[0] = new_LweSample(key->lwe_key->params);
  deref_boot_single(res, key, d1, ks_key, tab_and);
  lweCopy(result[1], res[0], key->lwe_key->params);
  d0.clear();
  d1.clear();
  res.clear();
}


void CDUP(vector <LweSample*> &result ,
	  LweSample* a,
	  vector <LweSample*> &b,
	  TFheGateBootstrappingSecretKeySet* key,
	  BaseBKeySwitchKey* ks_key){
  MULB(result, b, a, key, ks_key);
}


void NCDUP(vector <LweSample*> &result ,
	   LweSample* a,
	   vector <LweSample*> &b,
	   TFheGateBootstrappingSecretKeySet* key,
	   BaseBKeySwitchKey* ks_key){
  vector<LweSample*> tmp;
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  lweCopy(tmp[0], a, key->lwe_key->params);
  lweCopy(tmp[1], b[0], key->lwe_key->params);
  lweCopy(tmp[2], b[1], key->lwe_key->params);
  deref_boot_1KS(result, key, tmp, ks_key, tab_mul_spe);
}


void CSEL(vector <LweSample*> &result ,
	  LweSample* a,
	  vector <LweSample*> &b,
	  vector <LweSample*> &c,
	  TFheGateBootstrappingSecretKeySet* key,
	  BaseBKeySwitchKey* ks_key){
  vector<LweSample*> tmp, res, add1, add2;
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  res.push_back(new_LweSample(key->lwe_key->params));
  res.push_back(new_LweSample(key->lwe_key->params));
  res.push_back(new_LweSample(key->lwe_key->params));
  res.push_back(new_LweSample(key->lwe_key->params));
  add1.push_back(new_LweSample(key->lwe_key->params));
  add1.push_back(new_LweSample(key->lwe_key->params));
  add2.push_back(new_LweSample(key->lwe_key->params));
  add2.push_back(new_LweSample(key->lwe_key->params));

  word8* tab[256]={tab_mul_lsb, tab_mul_lsb, tab_mul_spe, tab_mul_spe};
  lweCopy(tmp[0], a, key->lwe_key->params);
  lweCopy(tmp[1], b[0], key->lwe_key->params);
  lweCopy(tmp[2], b[1], key->lwe_key->params);
  lweCopy(tmp[3], c[0], key->lwe_key->params);
  lweCopy(tmp[4], c[1], key->lwe_key->params);
  deref_boot_opti(res, key, tmp, ks_key, tab);
  
  lweCopy(add1[0], res[0], key->lwe_key->params);
  lweCopy(add1[1], res[1], key->lwe_key->params);
  lweCopy(add2[0], res[2], key->lwe_key->params);
  lweCopy(add2[1], res[3], key->lwe_key->params);

  ADDZ(result, add1, add2, key, ks_key);
}


void DIV(vector <LweSample*> &result ,
	 vector <LweSample*> &a,
	 vector <LweSample*> &b,
	 TFheGateBootstrappingSecretKeySet* key,
	 BaseBKeySwitchKey* ks_key){
  vector<LweSample*> tmp, tmp_sub, tmp_bool, tmp_mul, tmp_q, tmp_greater, tmp_div;
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp_sub.push_back(new_LweSample(key->lwe_key->params));
  tmp_sub.push_back(new_LweSample(key->lwe_key->params));
  tmp_bool.push_back(new_LweSample(key->lwe_key->params));
  tmp_bool.push_back(new_LweSample(key->lwe_key->params));
  tmp_bool.push_back(new_LweSample(key->lwe_key->params));
  tmp_mul.push_back(new_LweSample(key->lwe_key->params));
  tmp_mul.push_back(new_LweSample(key->lwe_key->params));
  tmp_q.push_back(new_LweSample(key->lwe_key->params));
  tmp_q.push_back(new_LweSample(key->lwe_key->params));
  tmp_greater.push_back(new_LweSample(key->lwe_key->params));
  tmp_greater.push_back(new_LweSample(key->lwe_key->params));
  tmp_div.push_back(new_LweSample(key->lwe_key->params));
  tmp_div.push_back(new_LweSample(key->lwe_key->params));

  word8 tab_zero[16]={1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
  word8 tab_div[256]={0};
  word8 tab_add_qi[256];  word8 tab_and_mulm_zero[256]={0};
  for(int i=0; i<16; i++){
    for(int j=0; j<16; j++)
      if(j==0)
	tab_div[16*i+j]=0;
      else 
      tab_div[16*i+j]= i/j;
  }
  lweCopy(tmp_div[0], a[0], key->lwe_key->params);
  lweCopy(tmp_div[1], b[1], key->lwe_key->params);
  deref_boot_single(tmp_div, key, tmp_div, ks_key, tab_div); // h/l' 
  deref_simple_boot(tmp_div, key, b, ks_key, 0, 1, tab_zero);//(h'==0)
  deref_boot_single(result, key, tmp_div, ks_key, tab_mul_lsb);// result[0] is h/l' * (h'==0)
  // We compute C_t
  lweCopy(result[1], b[1], key->lwe_key->params);
  deref_boot_single(tmp_div, key, result, ks_key, tab_mul_lsb); 
  lweCopy(tmp_div[1], tmp_div[0], key->lwe_key->params);
  lweCopy(tmp_div[0], a[0], key->lwe_key->params);
  deref_boot_single(tmp, key, tmp_div, ks_key, tab_sub_lsb);
  lweCopy(tmp[1], a[1], key->lwe_key->params);

  // We initialize Cq
  lweSymEncrypt(tmp_q[0], modSwitchToTorus32(0, 32), key->lwe_key->params->alpha_min, key->lwe_key);
  lweSymEncrypt(tmp_q[0], modSwitchToTorus32(0, 32), key->lwe_key->params->alpha_min, key->lwe_key);
  word8* tab[256]={tab_mul_lsb,tab_mul_lsb};

  //Now we compute result[1]
  for(int i=3; i>=0; i--){
    SHLi(tmp_mul, b, i, key, ks_key);   
    GTE(tmp_greater, tmp, tmp_mul, key, ks_key); // a> 2^i*b
    lweCopy(tmp_greater[0], b[0], key->lwe_key->params);
    for(int k=0; k<16; k++){
      for(int j=0; j<16; j++)
	tab_and_mulm_zero[16*k+j]=(((k<<i)>>4)==0) & (j==1);
    }
    deref_boot_single(tmp_bool, key, tmp_greater, ks_key, tab_and_mulm_zero); // mulm==0 and a>2^i*b
    lweCopy(tmp_bool[1], tmp_mul[0], key->lwe_key->params);
    lweCopy(tmp_bool[2], tmp_mul[1], key->lwe_key->params);
    deref_boot_opti(tmp_sub, key, tmp_bool, ks_key, tab);
    SUB(tmp, tmp, tmp_sub, key, ks_key);
    // tmp_q = tmp + 2^(i)*tmp_bool
    for(int k=0; k<16; k++){
      for(int j=0; j<16; j++){
	tab_add_qi[16*k+j] = k+(j!=0)*pow(2,i);
      }
    }
    lweCopy(tmp_q[1], tmp_bool[0], key->lwe_key->params);
    deref_boot_single(tmp_q, key, tmp_q, ks_key, tab_add_qi);
  }
  lweCopy(result[1], tmp_q[0], key->lwe_key->params);
}


void DIV4(vector <LweSample*> &result , vector <LweSample*> &a, LweSample* b, TFheGateBootstrappingSecretKeySet* key, BaseBKeySwitchKey* ks_key){
  vector <LweSample*> q0, q1, tmp, tmp_add, res;
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));

  res.push_back(new_LweSample(key->lwe_key->params));
  res.push_back(new_LweSample(key->lwe_key->params));
  res.push_back(new_LweSample(key->lwe_key->params));
  res.push_back(new_LweSample(key->lwe_key->params));
  res.push_back(new_LweSample(key->lwe_key->params));

  tmp_add.push_back(new_LweSample(key->lwe_key->params));
  tmp_add.push_back(new_LweSample(key->lwe_key->params));
  q0.push_back(new_LweSample(key->lwe_key->params));
  q0.push_back(new_LweSample(key->lwe_key->params));
  q1.push_back(new_LweSample(key->lwe_key->params));
  q1.push_back(new_LweSample(key->lwe_key->params));

  lweCopy(tmp[0], b, key->lwe_key->params);
  lweCopy(tmp[1], a[0], key->lwe_key->params);
  lweCopy(tmp[2], a[0], key->lwe_key->params);
  lweCopy(tmp[3], a[1], key->lwe_key->params);
  lweCopy(tmp[4], a[0], key->lwe_key->params);
  lweCopy(tmp[5], a[1], key->lwe_key->params);

  word8* tab[256]={tab_div_msb_1, tab_div_msb_2, tab_div_lsb, tab_mod_msb, tab_mod_lsb};
  deref_boot_opti(res, key, tmp, ks_key, tab);

  word8* tab_add[256]={tab_add_msb, tab_add_lsb};
  lweCopy(tmp[0], res[3], key->lwe_key->params);
  lweCopy(tmp[1], res[4], key->lwe_key->params);
  lweCopy(tmp[2], res[4], key->lwe_key->params);
  deref_boot_opti(tmp_add, key, tmp, ks_key, tab_add);

  lweCopy(tmp[0], b, key->lwe_key->params);
  lweCopy(tmp[1], tmp_add[0], key->lwe_key->params);
  lweCopy(tmp[2], tmp_add[1], key->lwe_key->params);
  word8* tabb[256]={tab_div_msb_2, tab_div_lsb};
  deref_boot_opti(tmp_add, key, tmp, ks_key, tabb);

  deref_boot_single(tmp_add, key, tmp_add, ks_key, tab_add_lsb);
 
  lweCopy(q1[0], res[2], key->lwe_key->params);
  lweCopy(q1[1], tmp_add[0], key->lwe_key->params);
  deref_boot_single(tmp_add, key, q1, ks_key, tab_add_lsb);

  lweCopy(tmp[0], res[1], key->lwe_key->params);
  lweCopy(tmp[1], tmp_add[0], key->lwe_key->params);
  lweCopy(tmp[2], tmp_add[0], key->lwe_key->params);
  deref_boot_opti(q0, key, tmp, ks_key, tab_add); 
  // q0[1] is result[1]

  lweCopy(q1[0], res[0], key->lwe_key->params);
  lweCopy(q1[1], q0[0], key->lwe_key->params);
  deref_boot_single(result, key, q1, ks_key, tab_add_lsb);
  lweCopy(result[1], q0[1], key->lwe_key->params);
    
}


void EQ(vector <LweSample*> &result ,
	vector <LweSample*> &a,
	vector <LweSample*> &b,
	TFheGateBootstrappingSecretKeySet* key,
	BaseBKeySwitchKey* ks_key){
  vector <LweSample*> tmp_msb, tmp_lsb;
  tmp_msb.push_back(new_LweSample(key->lwe_key->params));
  tmp_msb.push_back(new_LweSample(key->lwe_key->params));
  tmp_lsb.push_back(new_LweSample(key->lwe_key->params));
  tmp_lsb.push_back(new_LweSample(key->lwe_key->params));
  lweCopy(tmp_msb[0], a[0], key->lwe_key->params);
  lweCopy(tmp_msb[1], b[0], key->lwe_key->params);
  lweCopy(tmp_lsb[0], a[1], key->lwe_key->params);
  lweCopy(tmp_lsb[1], b[1], key->lwe_key->params);

  deref_boot_single(tmp_msb, key, tmp_msb, ks_key, tab_eq);
  deref_boot_single(tmp_lsb, key, tmp_lsb, ks_key, tab_eq);
  lweCopy(tmp_msb[1], tmp_lsb[0], key->lwe_key->params);
  
  deref_boot_single(result, key, tmp_msb, ks_key, tab_mul_lsb); 
  lweCopy(result[1], result[0], key->lwe_key->params);
  lweSymEncrypt(result[0], modSwitchToTorus32(0, 32), key->lwe_key->params->alpha_min, key->lwe_key);
}


void GT(vector <LweSample*> &result ,
	vector <LweSample*> &a,
	vector <LweSample*> &b,
	TFheGateBootstrappingSecretKeySet* key,
	BaseBKeySwitchKey* ks_key){
  vector <LweSample*> tmp_msb, tmp_lsb, tmp_eq;
  tmp_msb.push_back(new_LweSample(key->lwe_key->params));
  tmp_msb.push_back(new_LweSample(key->lwe_key->params));
  tmp_msb.push_back(new_LweSample(key->lwe_key->params));
  tmp_lsb.push_back(new_LweSample(key->lwe_key->params));
  tmp_lsb.push_back(new_LweSample(key->lwe_key->params));
  tmp_eq.push_back(new_LweSample(key->lwe_key->params));
  tmp_eq.push_back(new_LweSample(key->lwe_key->params));
  lweCopy(tmp_msb[0], b[0], key->lwe_key->params);
  lweCopy(tmp_msb[1], a[0], key->lwe_key->params);
  lweCopy(tmp_msb[2], a[0], key->lwe_key->params);
  lweCopy(tmp_lsb[0], a[1], key->lwe_key->params);
  lweCopy(tmp_lsb[1], b[1], key->lwe_key->params);

  word8 *tab[256]={tab_eq, tab_sup};

  deref_boot_opti(tmp_eq, key, tmp_msb, ks_key, tab);
  deref_boot_single(tmp_lsb, key, tmp_lsb, ks_key, tab_sup);

  lweCopy(tmp_lsb[1], tmp_eq[0], key->lwe_key->params);
  deref_boot_single(result, key, tmp_lsb, ks_key, tab_and); 

  lweCopy(result[1], tmp_eq[1], key->lwe_key->params);
  deref_boot_single(tmp_lsb, key, result, ks_key, tab_xor);
  
  lweCopy(result[1], tmp_lsb[0], key->lwe_key->params);
  lweSymEncrypt(result[0], modSwitchToTorus32(0, 32), key->lwe_key->params->alpha_min, key->lwe_key);
}


void GTE(vector <LweSample*> &result ,
	 vector <LweSample*> &a,
	 vector <LweSample*> &b,
	 TFheGateBootstrappingSecretKeySet* key,
	 BaseBKeySwitchKey* ks_key){
  vector <LweSample*> tmp_msb, tmp_lsb, tmp_eq;
  tmp_msb.push_back(new_LweSample(key->lwe_key->params));
  tmp_msb.push_back(new_LweSample(key->lwe_key->params));
  tmp_msb.push_back(new_LweSample(key->lwe_key->params));
  tmp_lsb.push_back(new_LweSample(key->lwe_key->params));
  tmp_lsb.push_back(new_LweSample(key->lwe_key->params));
  tmp_eq.push_back(new_LweSample(key->lwe_key->params));
  tmp_eq.push_back(new_LweSample(key->lwe_key->params));
  lweCopy(tmp_msb[0], b[0], key->lwe_key->params);
  lweCopy(tmp_msb[1], a[0], key->lwe_key->params);
  lweCopy(tmp_msb[2], a[0], key->lwe_key->params);
  lweCopy(tmp_lsb[0], a[1], key->lwe_key->params);
  lweCopy(tmp_lsb[1], b[1], key->lwe_key->params);

  word8 *tab[256]={tab_eq, tab_sup};
  
  deref_boot_opti(tmp_eq, key, tmp_msb, ks_key, tab);
  deref_boot_single(tmp_lsb, key, tmp_lsb, ks_key, tab_sup_eq);

  lweCopy(tmp_lsb[1], tmp_eq[0], key->lwe_key->params);
  deref_boot_single(result, key, tmp_lsb, ks_key, tab_and); 

  lweCopy(result[1], tmp_eq[1], key->lwe_key->params);
  deref_boot_single(result, key, result, ks_key, tab_xor);
  
  lweCopy(result[1], result[0], key->lwe_key->params);
  lweSymEncrypt(result[0], modSwitchToTorus32(0, 32), key->lwe_key->params->alpha_min, key->lwe_key);
}


void LT(vector <LweSample*> &result ,
	vector <LweSample*> &a,
	vector <LweSample*> &b,
	TFheGateBootstrappingSecretKeySet* key,
	BaseBKeySwitchKey* ks_key){
  vector <LweSample*> tmp_msb, tmp_lsb, tmp_eq;
  tmp_msb.push_back(new_LweSample(key->lwe_key->params));
  tmp_msb.push_back(new_LweSample(key->lwe_key->params));
  tmp_msb.push_back(new_LweSample(key->lwe_key->params));
  tmp_lsb.push_back(new_LweSample(key->lwe_key->params));
  tmp_lsb.push_back(new_LweSample(key->lwe_key->params));
  tmp_eq.push_back(new_LweSample(key->lwe_key->params));
  tmp_eq.push_back(new_LweSample(key->lwe_key->params));
  lweCopy(tmp_msb[0], b[0], key->lwe_key->params);
  lweCopy(tmp_msb[1], a[0], key->lwe_key->params);
  lweCopy(tmp_msb[2], a[0], key->lwe_key->params);
  lweCopy(tmp_lsb[0], a[1], key->lwe_key->params);
  lweCopy(tmp_lsb[1], b[1], key->lwe_key->params);

  word8 *tab[256]={tab_eq, tab_inf};
  
  deref_boot_opti(tmp_eq, key, tmp_msb, ks_key, tab);
  deref_boot_single(tmp_lsb, key, tmp_lsb, ks_key, tab_inf);

  lweCopy(tmp_lsb[1], tmp_eq[0], key->lwe_key->params);
  deref_boot_single(result, key, tmp_lsb, ks_key, tab_and); 

  lweCopy(result[1], tmp_eq[1], key->lwe_key->params);
  deref_boot_single(result, key, result, ks_key, tab_xor);
  
  lweCopy(result[1], result[0], key->lwe_key->params);
  lweSymEncrypt(result[0], modSwitchToTorus32(0, 32), key->lwe_key->params->alpha_min, key->lwe_key);
}


void LTE(vector <LweSample*> &result ,
	 vector <LweSample*> &a,
	 vector <LweSample*> &b,
	 TFheGateBootstrappingSecretKeySet* key,
	 BaseBKeySwitchKey* ks_key){
  vector <LweSample*> tmp_msb, tmp_lsb, tmp_eq;
  tmp_msb.push_back(new_LweSample(key->lwe_key->params));
  tmp_msb.push_back(new_LweSample(key->lwe_key->params));
  tmp_msb.push_back(new_LweSample(key->lwe_key->params));
  tmp_lsb.push_back(new_LweSample(key->lwe_key->params));
  tmp_lsb.push_back(new_LweSample(key->lwe_key->params));
  tmp_eq.push_back(new_LweSample(key->lwe_key->params));
  tmp_eq.push_back(new_LweSample(key->lwe_key->params));
  lweCopy(tmp_msb[0], b[0], key->lwe_key->params);
  lweCopy(tmp_msb[1], a[0], key->lwe_key->params);
  lweCopy(tmp_msb[2], a[0], key->lwe_key->params);
  lweCopy(tmp_lsb[0], a[1], key->lwe_key->params);
  lweCopy(tmp_lsb[1], b[1], key->lwe_key->params);

  word8 *tab[256]={tab_eq, tab_inf};
  
  deref_boot_opti(tmp_eq, key, tmp_msb, ks_key, tab);
  deref_boot_single(tmp_lsb, key, tmp_lsb, ks_key, tab_inf_eq);

  lweCopy(tmp_lsb[1], tmp_eq[0], key->lwe_key->params);
  deref_boot_single(result, key, tmp_lsb, ks_key, tab_and); 

  lweCopy(result[1], tmp_eq[1], key->lwe_key->params);
  deref_boot_single(result, key, result, ks_key, tab_xor);
  
  lweCopy(result[1], result[0], key->lwe_key->params);
  lweSymEncrypt(result[0], modSwitchToTorus32(0, 32), key->lwe_key->params->alpha_min, key->lwe_key);
}  

void MAX(vector <LweSample*> &result,
	  vector <LweSample*> &a,
	  vector <LweSample*> &b,
	  TFheGateBootstrappingSecretKeySet* key,
	  BaseBKeySwitchKey* ks_key ){
  vector<LweSample*> res, lsb, tmp, tmp_mul1;
  res.push_back(new_LweSample(key->lwe_key->params));
  res.push_back(new_LweSample(key->lwe_key->params));
  res.push_back(new_LweSample(key->lwe_key->params));
  res.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp_mul1.push_back(new_LweSample(key->lwe_key->params));
  tmp_mul1.push_back(new_LweSample(key->lwe_key->params));
  lweCopy(tmp[0], b[0], key->lwe_key->params);
  lweCopy(tmp[1], a[0], key->lwe_key->params);
  lweCopy(tmp[2], a[0], key->lwe_key->params);
  lweCopy(tmp[3], a[0], key->lwe_key->params);
  lweCopy(tmp[4], a[0], key->lwe_key->params);
  lsb.push_back(new_LweSample(key->lwe_key->params));
  lsb.push_back(new_LweSample(key->lwe_key->params));
  lsb.push_back(new_LweSample(key->lwe_key->params));
  word8 * tab[256]={tab_sup, tab_eq, tab_inf, tab_max};
  deref_boot_opti(res, key, tmp, ks_key, tab);
  // res[0]=(h>h'), res[1]=(h==h'), res[2]=(h<h'), res[3]=result[0]=max(h,h')
  lweCopy(lsb[0], b[1], key->lwe_key->params);
  lweCopy(lsb[1], res[2], key->lwe_key->params);
  lweCopy(lsb[2], a[1], key->lwe_key->params);
  word8 * tab2[256]={tab_mul_lsb, tab_max};
  deref_boot_opti(tmp_mul1, key, lsb, ks_key, tab2);
  lsb.pop_back();
  //2 mul : res[1]*a[1], res[2]*tmp_mul1[1]
  lweCopy(lsb[0], res[1], key->lwe_key->params);
  lweCopy(lsb[1], tmp_mul1[1], key->lwe_key->params);
  deref_boot_single(lsb, key, lsb, ks_key, tab_mul_lsb); // (h==h')*max(l,l')
  lweCopy(lsb[1], tmp_mul1[0], key->lwe_key->params);
  deref_boot_single(lsb, key, lsb, ks_key, tab_add_lsb);//(h==h')*max(l,l')+l'*(h<h')
  lweCopy(tmp_mul1[0], res[0], key->lwe_key->params);
  lweCopy(tmp_mul1[1], a[1], key->lwe_key->params);
  deref_boot_single(tmp_mul1, key, tmp_mul1, ks_key, tab_mul_lsb); //(h>h')*l
  lweCopy(tmp_mul1[1], lsb[0], key->lwe_key->params);
  deref_boot_single(lsb, key, tmp_mul1, ks_key, tab_add_lsb);

  lweCopy(result[0], res[3], key->lwe_key->params);
  lweCopy(result[1], lsb[0], key->lwe_key->params);
}


void  MIN(vector <LweSample*> &result,
	  vector <LweSample*> &a,
	  vector <LweSample*> &b,
	  TFheGateBootstrappingSecretKeySet* key,
	  BaseBKeySwitchKey* ks_key ){
  vector<LweSample*> res, lsb, tmp, tmp_mul1;
  res.push_back(new_LweSample(key->lwe_key->params));
  res.push_back(new_LweSample(key->lwe_key->params));
  res.push_back(new_LweSample(key->lwe_key->params));
  res.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp_mul1.push_back(new_LweSample(key->lwe_key->params));
  tmp_mul1.push_back(new_LweSample(key->lwe_key->params));
  lweCopy(tmp[0], b[0], key->lwe_key->params);
  lweCopy(tmp[1], a[0], key->lwe_key->params);
  lweCopy(tmp[2], a[0], key->lwe_key->params);
  lweCopy(tmp[3], a[0], key->lwe_key->params);
  lweCopy(tmp[4], a[0], key->lwe_key->params);
  lsb.push_back(new_LweSample(key->lwe_key->params));
  lsb.push_back(new_LweSample(key->lwe_key->params));
  lsb.push_back(new_LweSample(key->lwe_key->params));
  word8 * tab[256]={tab_inf, tab_eq, tab_sup, tab_min};
  deref_boot_opti(res, key, tmp, ks_key, tab);
  // res[0]=(h<h'), res[1]=(h==h'), res[2]=(h>h'), res[3]=result[0]=min(h,h')
  lweCopy(lsb[0], b[1], key->lwe_key->params);
  lweCopy(lsb[1], res[2], key->lwe_key->params);
  lweCopy(lsb[2], a[1], key->lwe_key->params);
  word8 * tab2[256]={tab_mul_lsb, tab_min};
  deref_boot_opti(tmp_mul1, key, lsb, ks_key, tab2);
  lsb.pop_back();
  // 2 mul : res[1]*a[1] , res[2]*tmp_mul1[1]
  lweCopy(lsb[0], res[1], key->lwe_key->params);
  lweCopy(lsb[1], tmp_mul1[1], key->lwe_key->params);
  deref_boot_single(lsb, key, lsb, ks_key, tab_mul_lsb); // (h==h')*min(l,l')
  lweCopy(lsb[1], tmp_mul1[0], key->lwe_key->params);
  deref_boot_single(lsb, key, lsb, ks_key, tab_add_lsb);//(h==h')*min(l,l')+l'*(h>h')
  lweCopy(tmp_mul1[0], res[0], key->lwe_key->params);
  lweCopy(tmp_mul1[1], a[1], key->lwe_key->params);
  deref_boot_single(tmp_mul1, key, tmp_mul1, ks_key, tab_mul_lsb); //(h<h')*l
  lweCopy(tmp_mul1[1], lsb[0], key->lwe_key->params);
  deref_boot_single(lsb, key, tmp_mul1, ks_key, tab_add_lsb);

  lweCopy(result[0], res[3], key->lwe_key->params);
  lweCopy(result[1], lsb[0], key->lwe_key->params);
}


void MOD(vector <LweSample*> &result ,
	 vector <LweSample*> &a,
	 vector<LweSample* > &b,
	 TFheGateBootstrappingSecretKeySet* key,
	 BaseBKeySwitchKey* ks_key){
  vector<LweSample*> tmp, tmp_sub, tmp_bool, tmp_mul, tmp_q, tmp_greater, tmp_div;
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp_sub.push_back(new_LweSample(key->lwe_key->params));
  tmp_sub.push_back(new_LweSample(key->lwe_key->params));
  tmp_bool.push_back(new_LweSample(key->lwe_key->params));
  tmp_bool.push_back(new_LweSample(key->lwe_key->params));
  tmp_bool.push_back(new_LweSample(key->lwe_key->params));
  tmp_mul.push_back(new_LweSample(key->lwe_key->params));
  tmp_mul.push_back(new_LweSample(key->lwe_key->params));
  tmp_q.push_back(new_LweSample(key->lwe_key->params));
  tmp_q.push_back(new_LweSample(key->lwe_key->params));
  tmp_greater.push_back(new_LweSample(key->lwe_key->params));
  tmp_greater.push_back(new_LweSample(key->lwe_key->params));
  tmp_div.push_back(new_LweSample(key->lwe_key->params));
  tmp_div.push_back(new_LweSample(key->lwe_key->params));

  word8 tab_zero[16]={1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
  word8 tab_div[256]={0};
  word8 tab_add_qi[256];  word8 tab_and_mulm_zero[256]={0};
  for(int i=0; i<16; i++){
    for(int j=0; j<16; j++)
      if(j==0)
	tab_div[16*i+j]=0;
      else 
      tab_div[16*i+j]= i/j;
  }
  lweCopy(tmp_div[0], a[0], key->lwe_key->params);
  lweCopy(tmp_div[1], b[1], key->lwe_key->params);
  deref_boot_single(tmp_div, key, tmp_div, ks_key, tab_div); // h/l' 
  deref_simple_boot(tmp_div, key, b, ks_key, 0, 1, tab_zero);//(h'==0)
  deref_boot_single(result, key, tmp_div, ks_key, tab_mul_lsb);// result[0] is h/l' * (h'==0)
  // We compute C_t
  lweCopy(result[1], b[1], key->lwe_key->params);
  deref_boot_single(tmp_div, key, result, ks_key, tab_mul_lsb); 
  lweCopy(tmp_div[1], tmp_div[0], key->lwe_key->params);
  lweCopy(tmp_div[0], a[0], key->lwe_key->params);
  deref_boot_single(tmp, key, tmp_div, ks_key, tab_sub_lsb);
  lweCopy(tmp[1], a[1], key->lwe_key->params);

  // We initialize Cq
  lweSymEncrypt(tmp_q[0], modSwitchToTorus32(0, 32), key->lwe_key->params->alpha_min, key->lwe_key);
  lweSymEncrypt(tmp_q[0], modSwitchToTorus32(0, 32), key->lwe_key->params->alpha_min, key->lwe_key);
  word8* tab[256]={tab_mul_lsb,tab_mul_lsb};

  //Now we compute result[1]
  for(int i=3; i>=0; i--){
    SHLi(tmp_mul, b, i, key, ks_key);   
    GTE(tmp_greater, tmp, tmp_mul, key, ks_key); // a> 2^i*b
    lweCopy(tmp_greater[0], b[0], key->lwe_key->params);
    for(int k=0; k<16; k++){
      for(int j=0; j<16; j++)
	tab_and_mulm_zero[16*k+j]=(((k<<i)>>4)==0) & (j==1);
    }
    deref_boot_single(tmp_bool, key, tmp_greater, ks_key, tab_and_mulm_zero); // mulm==0 and a>2^i*b
    lweCopy(tmp_bool[1], tmp_mul[0], key->lwe_key->params);
    lweCopy(tmp_bool[2], tmp_mul[1], key->lwe_key->params);
    deref_boot_opti(tmp_sub, key, tmp_bool, ks_key, tab);
    SUB(tmp, tmp, tmp_sub, key, ks_key);   
  }
  lweCopy(result[0], tmp[0], key->lwe_key->params);
  lweCopy(result[1], tmp[1], key->lwe_key->params);
}


void MOD4(vector <LweSample*> &result ,
	  vector <LweSample*> &a,
	  LweSample* b,
	  TFheGateBootstrappingSecretKeySet* key,
	  BaseBKeySwitchKey* ks_key){
  vector <LweSample*> tmp, res;
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  res.push_back(new_LweSample(key->lwe_key->params));
  res.push_back(new_LweSample(key->lwe_key->params));

  lweCopy(tmp[0], b, key->lwe_key->params);
  lweCopy(tmp[1], a[0], key->lwe_key->params);
  lweCopy(tmp[2], a[1], key->lwe_key->params);

  word8* tab[256]={tab_mod_msb, tab_mod_lsb};
  deref_boot_opti(res, key, tmp, ks_key, tab);

  lweCopy(tmp[0], res[0], key->lwe_key->params);
  lweCopy(tmp[1], res[1], key->lwe_key->params);
  lweCopy(tmp[2], res[1], key->lwe_key->params);
  word8* tabb[256]={tab_add_msb, tab_add_lsb};
  deref_boot_opti(res, key, tmp, ks_key, tabb);
 
  lweCopy(tmp[0], b, key->lwe_key->params);
  lweCopy(tmp[1], res[0], key->lwe_key->params);
  lweCopy(tmp[2], res[1], key->lwe_key->params);
  deref_boot_opti(res, key, tmp, ks_key, tab);
  deref_boot_single(result, key, res, ks_key, tab_add_lsb);
  lweCopy(result[1], result[0], key->lwe_key->params);
  lweSymEncrypt(result[0], modSwitchToTorus32(0, 32), key->lwe_key->params->alpha_min, key->lwe_key);


  
}


void MUL(vector<LweSample*> &result,
	 vector<LweSample*> &a,
	 vector<LweSample*> &b,
	 TFheGateBootstrappingSecretKeySet* key,
	 BaseBKeySwitchKey* ks_key){
  vector<LweSample*>  tmp, res, tmp_bis;
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  res.push_back(new_LweSample(key->lwe_key->params));
  res.push_back(new_LweSample(key->lwe_key->params));
  res.push_back(new_LweSample(key->lwe_key->params));
  lweCopy(tmp[0], a[1], key->lwe_key->params);
  lweCopy(tmp[1], b[1], key->lwe_key->params);
  lweCopy(tmp[2], b[1], key->lwe_key->params);
  lweCopy(tmp[3], b[0], key->lwe_key->params);
  tmp_bis.push_back(new_LweSample(key->lwe_key->params));
  tmp_bis.push_back(new_LweSample(key->lwe_key->params));
  lweCopy(tmp_bis[0], a[0], key->lwe_key->params);
  lweCopy(tmp_bis[1], b[1], key->lwe_key->params);

  word8* tab[256]={tab_mul_lsb, tab_mul_msb, tab_mul_lsb};
  deref_boot_opti(res, key, tmp, ks_key, tab);
  
  deref_boot_single(tmp_bis, key, tmp_bis, ks_key, tab_mul_lsb);
  lweCopy(tmp_bis[1], res[2], key->lwe_key->params);
  deref_boot_single(tmp_bis, key, tmp_bis, ks_key, tab_add_lsb);
  lweCopy(tmp_bis[1], res[1], key->lwe_key->params);
  deref_boot_single(result, key, tmp_bis, ks_key, tab_add_lsb);
  lweCopy(result[1], res[0], key->lwe_key->params);
  
}


void MULB(vector<LweSample*> &result,
	  vector<LweSample*> &a,
	  LweSample* b,
	  TFheGateBootstrappingSecretKeySet* key,
	  BaseBKeySwitchKey* ks_key){
  vector<LweSample*> tmp;
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  lweCopy(tmp[0], b, key->lwe_key->params);
  lweCopy(tmp[1], a[0], key->lwe_key->params);
  lweCopy(tmp[2], a[1], key->lwe_key->params);
  deref_boot_1KS(result, key, tmp, ks_key, tab_mul_lsb);
}


void MULM(vector<LweSample*> &result,
	  vector<LweSample*> &a,
	  vector<LweSample*> &b,
	  TFheGateBootstrappingSecretKeySet* key,
	  BaseBKeySwitchKey* ks_key){
  vector<LweSample*>  tmp, a0b1, a1b0, tmp4, tmp5, carry;
  vector<LweSample*> mv1, res1, mv2, res2;
  mv1.push_back(new_LweSample(key->lwe_key->params));
  mv1.push_back(new_LweSample(key->lwe_key->params));
  mv1.push_back(new_LweSample(key->lwe_key->params));
  mv1.push_back(new_LweSample(key->lwe_key->params));
  mv1.push_back(new_LweSample(key->lwe_key->params));
  res1.push_back(new_LweSample(key->lwe_key->params));
  res1.push_back(new_LweSample(key->lwe_key->params));
  res1.push_back(new_LweSample(key->lwe_key->params));
  res1.push_back(new_LweSample(key->lwe_key->params));
  mv2.push_back(new_LweSample(key->lwe_key->params));
  mv2.push_back(new_LweSample(key->lwe_key->params));
  mv2.push_back(new_LweSample(key->lwe_key->params));
  mv2.push_back(new_LweSample(key->lwe_key->params));
  res2.push_back(new_LweSample(key->lwe_key->params));
  res2.push_back(new_LweSample(key->lwe_key->params));
  res2.push_back(new_LweSample(key->lwe_key->params));

  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  a0b1.push_back(new_LweSample(key->lwe_key->params));
  a0b1.push_back(new_LweSample(key->lwe_key->params));
  a1b0.push_back(new_LweSample(key->lwe_key->params));
  a1b0.push_back(new_LweSample(key->lwe_key->params));
  carry.push_back(new_LweSample(key->lwe_key->params));
  carry.push_back(new_LweSample(key->lwe_key->params)); 
  tmp4.push_back(new_LweSample(key->lwe_key->params));
  tmp4.push_back(new_LweSample(key->lwe_key->params));
  tmp5.push_back(new_LweSample(key->lwe_key->params));
  tmp5.push_back(new_LweSample(key->lwe_key->params));
  
  lweCopy(mv1[0], a[0], key->lwe_key->params);
  lweCopy(mv1[1], b[0], key->lwe_key->params);
  lweCopy(mv1[2], b[0], key->lwe_key->params);
  lweCopy(mv1[3], b[1], key->lwe_key->params);
  lweCopy(mv1[4], b[1], key->lwe_key->params);

  word8* tab_mv1[256]={tab_mul_msb, tab_mul_lsb, tab_mul_msb, tab_mul_lsb};
  deref_boot_opti(res1, key, mv1, ks_key, tab_mv1);

  lweCopy(mv2[0], a[1], key->lwe_key->params);
  lweCopy(mv2[1], b[0], key->lwe_key->params);
  lweCopy(mv2[2], b[0], key->lwe_key->params);
  lweCopy(mv2[3], b[1], key->lwe_key->params);

  word8* tab_mv2[256]={tab_mul_msb, tab_mul_lsb, tab_mul_msb};
  deref_boot_opti(res2, key, mv2, ks_key, tab_mv2);

  
  word8* tab_add[256]={tab_add_msb, tab_add_lsb};
  // (1) lsb 
  lweCopy(tmp[0], res1[3], key->lwe_key->params); //lsn(hl')
  lweCopy(tmp[1], res2[1], key->lwe_key->params); //lsn(h'l)
  lweCopy(tmp[2], res2[1], key->lwe_key->params); 
  deref_boot_opti(tmp4, key, tmp, ks_key, tab_add); //lsn(hl')+ lsn(h'l) = (a,b) {16², 16}
  // (2) msb(16²) and carry(16³)
  lweCopy(tmp[0], res1[2], key->lwe_key->params); //msn(hl')
  lweCopy(tmp[1], res2[0], key->lwe_key->params); //msn(h'l)
  lweCopy(tmp[2], res2[0], key->lwe_key->params);
  deref_boot_opti(tmp5, key, tmp, ks_key, tab_add); // msn(hl') + msn(h'l) = (carry, msn) {16³, 16²}
  // a+msn = (carry2, msn2)
  lweCopy(tmp[0], tmp4[0], key->lwe_key->params); 
  lweCopy(tmp[1], tmp5[1], key->lwe_key->params);
  lweCopy(tmp[2], tmp5[1], key->lwe_key->params);
  deref_boot_opti(carry, key, tmp, ks_key, tab_add); // (carry2, msn2,b) {16³, 16², 16}

  lweCopy(tmp[0], tmp4[1], key->lwe_key->params); 
  lweCopy(tmp[1], res2[2], key->lwe_key->params);
  deref_boot_single(tmp4, key, tmp, ks_key, tab_add_msb); // (carry2, msn2) + (0, tmp4[0])
  
  lweCopy(tmp[0], carry[1], key->lwe_key->params); 
  lweCopy(tmp[1], tmp4[0], key->lwe_key->params);
  lweCopy(tmp[2], tmp4[0], key->lwe_key->params);
  deref_boot_opti(a0b1, key, tmp, ks_key, tab_add); // msn2 + tmp4[0] {16³, 16²}
  // (carry2,0) + (carry3, lsn)

  lweCopy(tmp[0], carry[0], key->lwe_key->params); 
  lweCopy(tmp[1], a0b1[0], key->lwe_key->params);
  deref_boot_single(carry, key, tmp, ks_key, tab_add_msb); //(carry4, lsn) {16³, 16²} in (carry[0], a0b1[1])

  lweCopy(tmp4[0], carry[0], key->lwe_key->params); 
  lweCopy(tmp4[1], a0b1[1], key->lwe_key->params);
  ADD(result, res1, tmp4, key, ks_key);
}


void OR(vector <LweSample*> &result,
	vector <LweSample*> &v1,
	vector <LweSample*> &v2,
	TFheGateBootstrappingSecretKeySet* key,
	BaseBKeySwitchKey* ks_key) {
  vector <LweSample*> d0;
  vector <LweSample*> d1;
  vector <LweSample*> res (1);
  d0.push_back(new_LweSample(key->lwe_key->params));
  d0.push_back(new_LweSample(key->lwe_key->params));
  d1.push_back(new_LweSample(key->lwe_key->params));
  d1.push_back(new_LweSample(key->lwe_key->params));
  lweCopy(d0[0], v1[0], key->lwe_key->params);
  lweCopy(d0[1], v2[0], key->lwe_key->params);
  lweCopy(d1[0], v1[1], key->lwe_key->params);
  lweCopy(d1[1], v2[1], key->lwe_key->params);
  deref_boot_single(result, key, d0, ks_key, tab_or);
  res[0] = new_LweSample(key->lwe_key->params);
  deref_boot_single(res, key, d1, ks_key, tab_or);
  lweCopy(result[1], res[0], key->lwe_key->params);
  d0.clear();
  d1.clear();
  res.clear();
}


void RC(vector<LweSample*> &result,
	vector<LweSample*> &a,
	TFheGateBootstrappingSecretKeySet* key,
	BaseBKeySwitchKey* ks_key){
  vector<LweSample*> bis, acc, tmp;
   bis.push_back(new_LweSample(key->lwe_key->params));
   bis.push_back(new_LweSample(key->lwe_key->params));
   acc.push_back(new_LweSample(key->lwe_key->params));
   acc.push_back(new_LweSample(key->lwe_key->params));
   tmp.push_back(new_LweSample(key->lwe_key->params));
   tmp.push_back(new_LweSample(key->lwe_key->params));

   word8 mul_8[16]={0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
   word8 mul_4[16]={0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
   word8 mul_2[16]={0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
   word8 id[16]={1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
   
   deref_simple_boot(result, key, a,  ks_key, 0, 0, mul_8);//8
   deref_simple_boot(bis, key, a,  ks_key, 1, 0, mul_4);//4
   lweAddTo(result[0], bis[0], key->lwe_key->params);
   deref_simple_boot(bis, key, a,  ks_key, 2, 0, mul_2);//2
   lweAddTo(result[0], bis[0], key->lwe_key->params);
   deref_simple_boot(bis, key, a,  ks_key, 3, 0, id);//1
   lweAddTo(result[0], bis[0], key->lwe_key->params);

   deref_simple_boot(acc, key, a,  ks_key, 4, 0, mul_8);//8
   deref_simple_boot(bis, key, a,  ks_key, 5, 0, mul_4);//4
   lweAddTo(acc[0], bis[0], key->lwe_key->params);
   deref_simple_boot(bis, key, a,  ks_key, 6, 0, mul_2);//2
   lweAddTo(acc[0], bis[0], key->lwe_key->params);
   deref_simple_boot(bis, key, a,  ks_key, 7, 0, id);//1
   lweAddTo(result[1], bis[0], key->lwe_key->params);
}


void ROL(vector <LweSample*> &result ,
	 vector <LweSample*> &a,
	 LweSample* b,
	 TFheGateBootstrappingSecretKeySet* key,
	 BaseBKeySwitchKey* ks_key){
  vector<LweSample*> res, tmp, v;
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  res.push_back(new_LweSample(key->lwe_key->params));
  res.push_back(new_LweSample(key->lwe_key->params));
  res.push_back(new_LweSample(key->lwe_key->params));
  res.push_back(new_LweSample(key->lwe_key->params));
  v.push_back(new_LweSample(key->lwe_key->params));
  v.push_back(new_LweSample(key->lwe_key->params));
  
  lweCopy(tmp[0], b, key->lwe_key->params);
  lweCopy(tmp[1], a[0], key->lwe_key->params);
  lweCopy(tmp[2], a[0], key->lwe_key->params);
  lweCopy(tmp[3], a[1], key->lwe_key->params);
  lweCopy(tmp[4], a[1], key->lwe_key->params);

  word8* tab[256]={tab_shift_left_msb, tab_shift_left_lsb, tab_shift_left_msb, tab_shift_left_lsb};
  deref_boot_opti(res, key, tmp, ks_key, tab);

  lweCopy(v[0], res[1], key->lwe_key->params);
  lweCopy(v[1], res[2], key->lwe_key->params);
  deref_boot_single(result, key, v, ks_key, tab_add_lsb);

  lweCopy(v[0], res[0], key->lwe_key->params);
  lweCopy(v[1], res[3], key->lwe_key->params);
  deref_boot_single(v, key, v, ks_key, tab_add_lsb);
  
  lweCopy(result[1], v[0], key->lwe_key->params);
}


void ROR(vector <LweSample*> &result ,
		    vector <LweSample*> &a,
		    LweSample* b,
		    TFheGateBootstrappingSecretKeySet* key,
		    BaseBKeySwitchKey* ks_key){
   vector<LweSample*> res, tmp, v;
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  res.push_back(new_LweSample(key->lwe_key->params));
  res.push_back(new_LweSample(key->lwe_key->params));
  res.push_back(new_LweSample(key->lwe_key->params));
  res.push_back(new_LweSample(key->lwe_key->params));
  v.push_back(new_LweSample(key->lwe_key->params));
  v.push_back(new_LweSample(key->lwe_key->params));
  
  lweCopy(tmp[0], b, key->lwe_key->params);
  lweCopy(tmp[1], a[0], key->lwe_key->params);
  lweCopy(tmp[2], a[0], key->lwe_key->params);
  lweCopy(tmp[3], a[1], key->lwe_key->params);
  lweCopy(tmp[4], a[1], key->lwe_key->params);

  word8* tab[256]={tab_shift_right_lsb, tab_shift_right_msb, tab_shift_right_msb, tab_shift_right_lsb};
  deref_boot_opti(res, key, tmp, ks_key, tab);

  lweCopy(v[0], res[1], key->lwe_key->params);
  lweCopy(v[1], res[3], key->lwe_key->params);
  deref_boot_single(result, key, v, ks_key, tab_add_lsb);

  lweCopy(v[0], res[0], key->lwe_key->params);
  lweCopy(v[1], res[2], key->lwe_key->params);
  deref_boot_single(v, key, v, ks_key, tab_add_lsb);
  
  lweCopy(result[1], v[0], key->lwe_key->params);
}


void SHL(vector <LweSample*> &result ,
	 vector <LweSample*> &a,
	 LweSample* b,
	 TFheGateBootstrappingSecretKeySet* key,
	 BaseBKeySwitchKey* ks_key){
  vector<LweSample*> tmp, res;
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  res.push_back(new_LweSample(key->lwe_key->params));
  res.push_back(new_LweSample(key->lwe_key->params));
  res.push_back(new_LweSample(key->lwe_key->params));
  lweCopy(tmp[0], b, key->lwe_key->params);
  lweCopy(tmp[1], a[0], key->lwe_key->params);
  lweCopy(tmp[2], a[1], key->lwe_key->params);
  lweCopy(tmp[3], a[1], key->lwe_key->params);
  word8* tab[256]={tab_shift_left_lsb, tab_shift_left_msb, tab_shift_left_lsb};
  deref_boot_opti(res, key, tmp, ks_key, tab); 
  deref_boot_single(result, key, res, ks_key, tab_add_lsb);
  lweCopy(result[1], res[2], key->lwe_key->params);
}


void SHR(vector <LweSample*> &result ,
	vector <LweSample*> &a,
	LweSample* b,
	TFheGateBootstrappingSecretKeySet* key,
	BaseBKeySwitchKey* ks_key){
  vector<LweSample*> tmp, res;
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  res.push_back(new_LweSample(key->lwe_key->params));
  res.push_back(new_LweSample(key->lwe_key->params));
  res.push_back(new_LweSample(key->lwe_key->params));
  lweCopy(tmp[0], b, key->lwe_key->params);
  lweCopy(tmp[1], a[0], key->lwe_key->params);
  lweCopy(tmp[2], a[1], key->lwe_key->params);
  lweCopy(tmp[3], a[0], key->lwe_key->params);
  word8* tab[256]={tab_shift_right_lsb, tab_shift_right_msb, tab_shift_right_msb};
  deref_boot_opti(res, key, tmp, ks_key, tab); 
  deref_boot_single(tmp, key, res, ks_key, tab_add_lsb);
  lweCopy(result[0], res[2], key->lwe_key->params);
  lweCopy(result[1], tmp[0], key->lwe_key->params);
}


void SUB(vector<LweSample*> &result,
	 vector<LweSample*> &a,
	 vector<LweSample*> &b,
	 TFheGateBootstrappingSecretKeySet* key,
	 BaseBKeySwitchKey* ks_key){
  vector<LweSample*> lsb, msb, carry, tmp;
  lsb.push_back(new_LweSample(key->lwe_key->params));
  lsb.push_back(new_LweSample(key->lwe_key->params));
  lsb.push_back(new_LweSample(key->lwe_key->params));
  msb.push_back(new_LweSample(key->lwe_key->params));
  msb.push_back(new_LweSample(key->lwe_key->params));
  lweCopy(lsb[0], b[1], key->lwe_key->params);
  lweCopy(lsb[1], a[1], key->lwe_key->params);
  lweCopy(lsb[2], a[1], key->lwe_key->params);
  lweCopy(msb[0], a[0], key->lwe_key->params);
  lweCopy(msb[1], b[0], key->lwe_key->params);
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  word8 *tab[256]={tab_sub_msb, tab_sub_lsb};

  deref_boot_opti(tmp, key, lsb, ks_key, tab);
  carry.push_back(tmp[0]);
  deref_boot_single(result, key, msb, ks_key, tab_sub_lsb);
  carry.push_back(result[0]);
  deref_boot_single(carry, key, carry, ks_key, tab_add_lsb);
  lweCopy(result[0], carry[0], key->lwe_key->params);
  lweCopy(result[1], tmp[1], key->lwe_key->params);
}


void XOR(vector <LweSample*> &result,
	 vector <LweSample*> &v1,
	 vector <LweSample*> &v2,
	 TFheGateBootstrappingSecretKeySet* key,
	 BaseBKeySwitchKey* ks_key) {
  vector <LweSample*> d0;
  vector <LweSample*> d1;
  vector <LweSample*> res (1);
  d0.push_back(new_LweSample(key->lwe_key->params));
  d0.push_back(new_LweSample(key->lwe_key->params));
  d1.push_back(new_LweSample(key->lwe_key->params));
  d1.push_back(new_LweSample(key->lwe_key->params));
  lweCopy(d0[0], v1[0], key->lwe_key->params);
  lweCopy(d0[1], v2[0], key->lwe_key->params);
  lweCopy(d1[0], v1[1], key->lwe_key->params);
  lweCopy(d1[1], v2[1], key->lwe_key->params);
  deref_boot_single(result, key, d0, ks_key, tab_xor);
  res[0] = new_LweSample(key->lwe_key->params);
  deref_boot_single(res, key, d1, ks_key, tab_xor);
  lweCopy(result[1], res[0], key->lwe_key->params);
  d0.clear();
  d1.clear();
  res.clear();
}


























