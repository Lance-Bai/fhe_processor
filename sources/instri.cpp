#include "instri.h"
#include "tables.h"
#include "bootstrapping.h"
#include <stdlib.h>
#include <math.h>

// This file implements the univariate instructions of the set in alphabetical order.


void ABS(vector <LweSample*> &result ,
	 vector <LweSample*> &a,
	 TFheGateBootstrappingSecretKeySet* key,
	 BaseBKeySwitchKey* ks_key){
  vector<LweSample*> tmp;
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  lweCopy(tmp[0], a[1], key->lwe_key->params);
  lweCopy(tmp[1], a[0], key->lwe_key->params);
  lweCopy(tmp[2], a[0], key->lwe_key->params);
  word8* tab[256]={tab_abs_msb, tab_abs_lsb};
  deref_boot_opti(result, key, tmp, ks_key, tab);
}


void ADDi(vector<LweSample*> &result,
	  vector<LweSample*> &a,
	  word8 b,
	  TFheGateBootstrappingSecretKeySet* key,
	  BaseBKeySwitchKey* ks_key){
  vector<LweSample*> tmp;
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));;
  lweCopy(tmp[0], a[1], key->lwe_key->params);
  lweCopy(tmp[1], a[0], key->lwe_key->params);
  lweCopy(tmp[2], a[0], key->lwe_key->params);
  word8 tab_msb[256]={};
  word8 tab_lsb[16]={};
  for(int i=0; i<16; i++)
    tab_lsb[i]= (i+b %256) %16;
  for(int i=0; i<256; i++){
    tab_msb[i]= (i+b %256) /16;   
  }
  word8* tab[]={tab_msb, tab_lsb};
  deref_boot_opti_2(result, key, tmp, ks_key, 1, tab);
}


void ANDi(vector <LweSample*> &result,
	  vector <LweSample*> &v1,
	  word8 b,
	  TFheGateBootstrappingSecretKeySet* key,
	  BaseBKeySwitchKey* ks_key){
  word8 tab_lsb[16]={};
  word8 tab_msb[16]={};
  word8 b_lsb = b%16;
  word8 b_msb = b/16;
  for(word8 i=0; i<16; i++){
    tab_lsb[i]= (i&b_lsb);
    tab_msb[i]= (i&b_msb);
  }
  deref_simple_boot(result, key, v1,  ks_key, 0, 0, tab_msb);
  deref_simple_boot(result, key, v1,  ks_key, 1, 1, tab_lsb);
}


void CDUPi(vector <LweSample*> &result,
	   LweSample* a,
	   word8 b,
	   TFheGateBootstrappingSecretKeySet* key,
	   BaseBKeySwitchKey* ks_key){
  vector<LweSample*> tmp;
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  lweCopy(tmp[0], a, key->lwe_key->params);
  word8 v = b/16;
  word8 vv = b%16;
  word8 t1[16]= {0,v,v,v,v,v,v,v,v,v,v,v,v,v,v,v};
  word8 t2[16]= {0,vv,vv,vv,vv,vv,vv,vv,vv,vv,vv,vv,vv,vv,vv,vv};
  word8* tab[16]={t1,t2}; 
  deref_simple_boot_opti(result, key, tmp, ks_key, tab);
}


void DC(vector<LweSample*> &result,
	vector<LweSample*> &a,
	TFheGateBootstrappingSecretKeySet* key,
	BaseBKeySwitchKey* ks_key){
  vector<LweSample*> bis, tmp;
   bis.push_back(new_LweSample(key->lwe_key->params));
   bis.push_back(new_LweSample(key->lwe_key->params));
   bis.push_back(new_LweSample(key->lwe_key->params));
   bis.push_back(new_LweSample(key->lwe_key->params));
   tmp.push_back(new_LweSample(key->lwe_key->params));

   deref_decompo(bis, key, a,ks_key);

   lweCopy(result[0], bis[0], key->lwe_key->params);
   lweCopy(result[1], bis[1], key->lwe_key->params);
   lweCopy(result[2], bis[2], key->lwe_key->params);
   lweCopy(result[3], bis[3], key->lwe_key->params);

   lweCopy(tmp[0], a[1], key->lwe_key->params);

   deref_decompo(bis, key, tmp,ks_key);

   lweCopy(result[4], bis[0], key->lwe_key->params);
   lweCopy(result[5], bis[1], key->lwe_key->params);
   lweCopy(result[6], bis[2], key->lwe_key->params);
   lweCopy(result[7], bis[3], key->lwe_key->params);
}


void DIVi(vector <LweSample*> &result ,
	  vector <LweSample*> &a,
	  word8 b,
	  TFheGateBootstrappingSecretKeySet* key,
	  BaseBKeySwitchKey* ks_key){
  vector<LweSample*> tmp;
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));;
  lweCopy(tmp[0], a[1], key->lwe_key->params);
  lweCopy(tmp[1], a[0], key->lwe_key->params);
  lweCopy(tmp[2], a[0], key->lwe_key->params);
  word8 tab_msb[256]={0};
  word8 tab_lsb[256]={0};
  for(int i=0; i<256; i++){
    if(b==0){
      break;
    }
    else{
      tab_msb[i]= ((i/b) /16)%16;
      tab_lsb[i]= (i/b) %16;
    }
  }
  word8* tab[]={tab_msb, tab_lsb};
  deref_boot_opti(result, key, tmp, ks_key, tab);
}


void DIV4i(vector <LweSample*> &result ,
	   vector <LweSample*> &a,
	   word8 b,
	   TFheGateBootstrappingSecretKeySet* key,
	   BaseBKeySwitchKey* ks_key){
  vector<LweSample*> tmp;
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));;
  lweCopy(tmp[0], a[1], key->lwe_key->params);
  lweCopy(tmp[1], a[0], key->lwe_key->params);
  lweCopy(tmp[2], a[0], key->lwe_key->params);
  word8 tab_msb[256]={0};
  word8 tab_lsb[256]={0};
  tab_msb[0]=0;
  tab_lsb[0]=0;
  for(int i=1; i<256; i++){
    if (b==0)
      break;
    else{
      tab_msb[i]= (i/b)/16;
      tab_lsb[i]= (i/b)%16;
    }
  }
  word8 * tab[256]={tab_msb, tab_lsb};
  deref_boot_opti(result, key, tmp, ks_key, tab);
}


void DIV_DECi(vector <LweSample*> &result ,
	      vector <LweSample*> &a,
	      word8 b,
	      TFheGateBootstrappingSecretKeySet* key,
	      BaseBKeySwitchKey* ks_key){
  vector<LweSample*> tmp;
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));;
  lweCopy(tmp[0], a[1], key->lwe_key->params);
  lweCopy(tmp[1], a[0], key->lwe_key->params);
  lweCopy(tmp[2], a[0], key->lwe_key->params);
  word8 tab_msb[256]={0};
  word8 tab_lsb[256]={0};
  for(float i=0; i<256; i++){
    if(b==0){
      break;
    }
    else{
      float f = floor(i/b);
      float g = (i/b) -f;
      g= round(g*256);
      tab_msb[(int)i]=  (word8)(g /16);
      tab_lsb[(int)i]=  (word8)g %16;
    }
  }
  word8* tab[]={tab_msb, tab_lsb};
  deref_boot_opti(result, key, tmp, ks_key, tab);
}


void EQi(vector <LweSample*> &result ,
	 vector <LweSample*> &a,
	 word8 b,
	 TFheGateBootstrappingSecretKeySet* key,
	 BaseBKeySwitchKey* ks_key){
  word8 tab [256]={};
  for(int i=0; i<256; i++){
    tab[i]= (i==b);
  }
  deref_boot_single(result, key, a, ks_key, tab);
  lweCopy(result[1], result[0], key->lwe_key->params);
  lweSymEncrypt(result[0], modSwitchToTorus32(0, 32), key->lwe_key->params->alpha_min, key->lwe_key);
}



void GTi(vector <LweSample*> &result ,
	 vector <LweSample*> &a,
	 word8 b,
	 TFheGateBootstrappingSecretKeySet* key,
	 BaseBKeySwitchKey* ks_key){
  word8 tab [256]={};
  for(int i=0; i<256; i++){
    tab[i]= (i>b);
  }
  deref_boot_single(result, key, a, ks_key, tab);
  lweCopy(result[1], result[0], key->lwe_key->params);
  lweSymEncrypt(result[0], modSwitchToTorus32(0, 32), key->lwe_key->params->alpha_min, key->lwe_key);
}


void GTEi(vector <LweSample*> &result ,
	  vector <LweSample*> &a,
	  word8 b,
	  TFheGateBootstrappingSecretKeySet* key,
	  BaseBKeySwitchKey* ks_key){
  word8 tab [256]={};
  for(int i=0; i<256; i++){
    tab[i]= (i>=b);
  }
  deref_boot_single(result, key, a, ks_key, tab);
  lweCopy(result[1], result[0], key->lwe_key->params);
  lweSymEncrypt(result[0], modSwitchToTorus32(0, 32), key->lwe_key->params->alpha_min, key->lwe_key);
}


void LTi(vector <LweSample*> &result ,
	 vector <LweSample*> &a,
	 word8 b,
	 TFheGateBootstrappingSecretKeySet* key,
	 BaseBKeySwitchKey* ks_key){
  word8 tab_inf [256]={};
  for(int i=0; i<256; i++){
    tab_inf[i]= (i<b);
  }
  deref_boot_single(result, key, a, ks_key, tab_inf);  
  lweCopy(result[1], result[0], key->lwe_key->params);
  lweSymEncrypt(result[0], modSwitchToTorus32(0, 32), key->lwe_key->params->alpha_min, key->lwe_key);
}


void LTEi(vector <LweSample*> &result ,
	  vector <LweSample*> &a,
	  word8 b,
	  TFheGateBootstrappingSecretKeySet* key,
	  BaseBKeySwitchKey* ks_key){
  word8 tab[256]={};
  for(int i=0; i<256; i++){
    tab[i]= (i<=b);
  }
  deref_boot_single(result, key, a, ks_key, tab);
  lweCopy(result[1], result[0], key->lwe_key->params);
  lweSymEncrypt(result[0], modSwitchToTorus32(0, 32), key->lwe_key->params->alpha_min, key->lwe_key);
}


void MAXi(vector <LweSample*> &result ,
	  vector <LweSample*> &a,
	  word8 b,
	  TFheGateBootstrappingSecretKeySet* key,
	  BaseBKeySwitchKey* ks_key){
  vector<LweSample*> tmp;
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));;
  lweCopy(tmp[0], a[1], key->lwe_key->params);
  lweCopy(tmp[1], a[0], key->lwe_key->params);
  lweCopy(tmp[2], a[0], key->lwe_key->params);
  word8 tab_msb[256];
  word8 tab_lsb[256];
  for(int i=0; i<256; i++){
    if(i<=b){
      tab_msb[i]= b/16;
      tab_lsb[i]= b%16;
    }else{
      tab_msb[i]= i/16;
      tab_lsb[i]= i%16;
    }
  }
  word8* tab[256]={tab_msb, tab_lsb};
  deref_boot_opti(result, key, tmp, ks_key, tab); 
}


void MINi(vector <LweSample*> &result ,
	  vector <LweSample*> &a,
	  word8 b,
	  TFheGateBootstrappingSecretKeySet* key,
	  BaseBKeySwitchKey* ks_key){
  vector<LweSample*> tmp;
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));;
  lweCopy(tmp[0], a[1], key->lwe_key->params);
  lweCopy(tmp[1], a[0], key->lwe_key->params);
  lweCopy(tmp[2], a[0], key->lwe_key->params);
  word8 tab_msb[256];
  word8 tab_lsb[256];
  for(int i=0; i<256; i++){
    if(i>=b){
      tab_msb[i]= b/16;
      tab_lsb[i]= b%16;
    }else{
      tab_msb[i]= i/16;
      tab_lsb[i]= i%16;
    }
  }
  word8* tab[256]={tab_msb, tab_lsb};
  deref_boot_opti(result, key, tmp, ks_key, tab); 
}


void MODi(vector <LweSample*> &result ,
	  vector <LweSample*> &a,
	  word8 b,
	  TFheGateBootstrappingSecretKeySet* key,
	  BaseBKeySwitchKey* ks_key){
  vector<LweSample*> tmp;
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));;
  lweCopy(tmp[0], a[1], key->lwe_key->params);
  lweCopy(tmp[1], a[0], key->lwe_key->params);
  lweCopy(tmp[2], a[0], key->lwe_key->params);
  word8 tab_msb[256]={0};
  word8 tab_lsb[256]={0};
  for(int i=0; i<256; i++){
    if(b==0)
      break;
    else{
      tab_msb[i]= (i%b) /16;
      tab_lsb[i]= (i%b) %16;
    }
  }
  word8* tab[256]={tab_msb, tab_lsb};
  deref_boot_opti(result, key, tmp, ks_key, tab); 
}


void MOD4i(vector <LweSample*> &result ,
	   vector <LweSample*> &a,
	   word8 b,
	   TFheGateBootstrappingSecretKeySet* key,
	   BaseBKeySwitchKey* ks_key){
  word8 tab[256]={0};
  for(int i=1; i<256; i++){
    tab[i]= i%b;
  }
  deref_boot_single(result, key, a, ks_key, tab);
  lweCopy(result[1], result[0], key->lwe_key->params);
  lweSymEncrypt(result[0], modSwitchToTorus32(0, 32), key->lwe_key->params->alpha_min, key->lwe_key);
}


void MULi(vector<LweSample*> &result,
	  vector<LweSample*> &a,
	  word8 b,
	  TFheGateBootstrappingSecretKeySet* key,
	  BaseBKeySwitchKey* ks_key){
  vector<LweSample*> tmp;
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));;
  lweCopy(tmp[0], a[1], key->lwe_key->params);
  lweCopy(tmp[1], a[0], key->lwe_key->params);
  lweCopy(tmp[2], a[0], key->lwe_key->params);
  word8 tab_msb[256]={};
  word8 tab_lsb[16]={};
  for(int i=0; i<16; i++)
    tab_lsb[i]= (i*b) %16;
  for(int i=0; i<256; i++){
    tab_msb[i]= ((i*b) /16)%16;    
  }
  word8* tab[]={tab_msb, tab_lsb};
  deref_boot_opti_2(result, key, tmp, ks_key, 1, tab);
}


void MULMi(vector<LweSample*> &result,
	   vector<LweSample*> &a,
	   word8 b,
	   TFheGateBootstrappingSecretKeySet* key,
	   BaseBKeySwitchKey* ks_key){
  vector<LweSample*> tmp;
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));;
  lweCopy(tmp[0], a[1], key->lwe_key->params);
  lweCopy(tmp[1], a[0], key->lwe_key->params);
  lweCopy(tmp[2], a[0], key->lwe_key->params);
  word8 tab_msb[256]={};
  word8 tab_lsb[256]={};
  word8 t=0;
  for(int i=0; i<256; i++){
    t = (i*b)/256;
    tab_msb[i]= t /16;
    tab_lsb[i]= t %16;
    //printf("%d, ", t%16);
  }
  //printf("\n");
  word8* tab[]={tab_msb, tab_lsb};
  deref_boot_opti(result, key, tmp, ks_key, tab);
}


void NEG(vector <LweSample*> &result,
	 vector <LweSample*> &a,
	 TFheGateBootstrappingSecretKeySet* key,
	 BaseBKeySwitchKey* ks_key){
  vector<LweSample*> tmp;
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  lweCopy(tmp[0], a[1], key->lwe_key->params);
  lweCopy(tmp[1], a[0], key->lwe_key->params);
  lweCopy(tmp[2], a[0], key->lwe_key->params);
  word8* tab[256]={tab_neg_msb, tab_neg_lsb};
  deref_boot_opti(result, key, tmp, ks_key, tab);
}


void ORi(vector <LweSample*> &result,
	 vector <LweSample*> &v1,
	 word8 b,
	 TFheGateBootstrappingSecretKeySet* key,
	 BaseBKeySwitchKey* ks_key){
  word8 tab_lsb[16]={};
  word8 tab_msb[16]={};
  word8 b_lsb = b%16;
  word8 b_msb = b/16;
  for(word8 i=0; i<16; i++){
    tab_lsb[i]= (i|b_lsb);
    tab_msb[i]= (i|b_msb);
  }
  deref_simple_boot(result, key, v1,  ks_key, 0, 0, tab_msb);
  deref_simple_boot(result, key, v1,  ks_key, 1, 1, tab_lsb);
}


void ROLi(vector <LweSample*> &result,
	  vector <LweSample*> &a,
	  word8 b,
	  TFheGateBootstrappingSecretKeySet* key,
	  BaseBKeySwitchKey* ks_key){
  vector<LweSample*> tmp_lsb;
  tmp_lsb.push_back(new_LweSample(key->lwe_key->params));
  tmp_lsb.push_back(new_LweSample(key->lwe_key->params));
  // On génère les tables à la volée
  word8 tab_msb[16]={};
  word8 tab_lsb[16]={};
  for(word8 i=0; i<16; i++){
    if(b<=4){
      tab_msb[i]= i>>(4-b) &0xf;
      tab_lsb[i]= i<<b  &0xf;
    }
      else if(b<=8){
	tab_msb[i]= i<<(b-4) &0xf;
	if(b!=8)
	  tab_lsb[i]= i>>(4-b%4) &0xf;
	else
	  tab_lsb[i]= i<<(b%4) &0xf;
      }
      else if(b<=12){
	tab_msb[i]= i>>(4-b%8) &0xf;
	tab_lsb[i]= i<<(b%4) &0xf;
      }
      else{
	tab_msb[i]= i<<(b%8-4) &0xf;;
	tab_lsb[i]= i>>(4-b%4) &0xf;;
    }
  }

  deref_simple_boot(result, key, a,  ks_key, 1, 0, tab_msb);
  deref_simple_boot(result, key, a,  ks_key, 0, 1, tab_msb);
  deref_simple_boot(tmp_lsb, key, a,  ks_key, 0, 0, tab_lsb);
  deref_simple_boot(tmp_lsb, key, a,  ks_key, 1, 1, tab_lsb);
  lweAddTo(result[0], tmp_lsb[0], key->lwe_key->params);
  lweAddTo(result[1], tmp_lsb[1], key->lwe_key->params);  
}



void RORi(vector <LweSample*> &result,
	  vector <LweSample*> &a,
	  word8 b,
	  TFheGateBootstrappingSecretKeySet* key,
	  BaseBKeySwitchKey* ks_key){
  vector<LweSample*> tmp_lsb;
  tmp_lsb.push_back(new_LweSample(key->lwe_key->params));
  tmp_lsb.push_back(new_LweSample(key->lwe_key->params));
  // On génère les tables à la volée
  word8 tab_msb[16]={};
  word8 tab_lsb[16]={};
  for(word8 i=0; i<16; i++){
    if(b<=4){
      tab_msb[i]= i>>b &0xf;
      tab_lsb[i]= i<<(4-b)  &0xf;
    }
      else if(b<=8){
	tab_msb[i]= i<<(8-b) &0xf;
	tab_lsb[i]= i>>(b-4) &0xf;
      }
      else if(b<=11){
	tab_msb[i]= i>>(b%4) &0xf;
	tab_lsb[i]= i<<(4-b%4) &0xf;
      }
      else{
	tab_msb[i]= i<<(8-b%8) &0xf;;
	tab_lsb[i]= i>>(b%8-4) &0xf;;
    }
  }
  deref_simple_boot(result, key, a,  ks_key, 0, 0, tab_msb);
  deref_simple_boot(result, key, a,  ks_key, 1, 1, tab_msb);
  deref_simple_boot(tmp_lsb, key, a,  ks_key, 0, 0, tab_lsb);
  deref_simple_boot(tmp_lsb, key, a,  ks_key, 1, 1, tab_lsb);
  lweAddTo(result[0], tmp_lsb[1], key->lwe_key->params);
  lweAddTo(result[1], tmp_lsb[0], key->lwe_key->params);
}


void SHLi(vector <LweSample*> &result,
	  vector <LweSample*> &a,
	  word8 b,
	  TFheGateBootstrappingSecretKeySet* key,
	  BaseBKeySwitchKey* ks_key){
  if(b>=8){
    lweSymEncrypt(result[0], modSwitchToTorus32(0, 32), key->lwe_key->params->alpha_min, key->lwe_key);
    lweSymEncrypt(result[1], modSwitchToTorus32(0, 32), key->lwe_key->params->alpha_min, key->lwe_key);
  }
  else if(b==4){
    lweCopy(result[0], a[1], key->lwe_key->params);
    lweSymEncrypt(result[1], modSwitchToTorus32(0, 32), key->lwe_key->params->alpha_min, key->lwe_key);
  }
  else if (b==0){
    lweCopy(result[0], a[0], key->lwe_key->params);
    lweCopy(result[1], a[1], key->lwe_key->params);
  }
  else{
    word8 tab_msb[16]={};
    word8 tab_lsb[16]={};
    for(int i=0; i<16; i++){
      tab_msb[i]= (i<<b) >>4 &0xf;
      tab_lsb[i]= i<<b & 0xf;
    }
  deref_simple_boot(result, key, a,  ks_key, 0, 0, tab_lsb);
  deref_simple_boot(result, key, a,  ks_key, 1, 1, tab_msb);
  lweAddTo(result[0], result[1], key->lwe_key->params);
  deref_simple_boot(result, key, a,  ks_key, 1, 1, tab_lsb);
  }
}


void SHRi(vector <LweSample*> &result,
	  vector <LweSample*> &a,
	  word8 b,
	  TFheGateBootstrappingSecretKeySet* key,
	  BaseBKeySwitchKey* ks_key){
  if(b>=8){
    lweSymEncrypt(result[0], modSwitchToTorus32(0, 32), key->lwe_key->params->alpha_min, key->lwe_key);
    lweSymEncrypt(result[1], modSwitchToTorus32(0, 32), key->lwe_key->params->alpha_min, key->lwe_key);
  }
  else if(b==4){
    lweCopy(result[1], a[0], key->lwe_key->params);
    lweSymEncrypt(result[0], modSwitchToTorus32(0, 32), key->lwe_key->params->alpha_min, key->lwe_key);
  }
  else if (b==0){
    lweCopy(result[0], a[0], key->lwe_key->params);
    lweCopy(result[1], a[1], key->lwe_key->params);
  }
  else{
    word8 tab_msb[16]={};
    word8 tab_lsb[16]={};
    for(int i=0; i<16; i++){
      tab_lsb[i]= (i<<4)>>b &0xf;
      tab_msb[i]= i>>b &0xf;
    }
    deref_simple_boot(result, key, a,  ks_key, 1, 0, tab_msb);
    deref_simple_boot(result, key, a,  ks_key, 0, 1, tab_lsb);
    lweAddTo(result[1], result[0], key->lwe_key->params);
    deref_simple_boot(result, key, a,  ks_key, 0, 0, tab_msb);
  }
}


void SUBi(vector<LweSample*> &result,
	  vector<LweSample*> &a,
	  word8 b,
	  TFheGateBootstrappingSecretKeySet* key,
	  BaseBKeySwitchKey* ks_key){
  vector<LweSample*> tmp;
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));;
  lweCopy(tmp[0], a[1], key->lwe_key->params);
  lweCopy(tmp[1], a[0], key->lwe_key->params);
  lweCopy(tmp[2], a[0], key->lwe_key->params);
  word8 tab_msb[256]={};
  word8 tab_lsb[16]={};
  for(int i=0; i<16; i++){
    int t = i-b;
    if(t<0) t= t+256;
    tab_lsb[i]= t %16;
  }
  for(int i=0; i<256; i++){
    int t = i-b;
    if(t<0) t= t+256;
    tab_msb[i]= t / 16;  
  }
  word8* tab[]={tab_msb, tab_lsb};
  deref_boot_opti_2(result, key, tmp, ks_key, 1, tab);
}



void TZR(vector <LweSample*> &result,
	 vector <LweSample*> &a,
	 TFheGateBootstrappingSecretKeySet* key,
	 BaseBKeySwitchKey* ks_key){
  word8 tab[256];
  tab[0]=1;
  for(int i=1; i<256; i++)
    tab[i]=0;  
  deref_boot_single(result, key, a, ks_key, tab); 
  lweCopy(result[1], result[0], key->lwe_key->params);
  lweSymEncrypt(result[0], modSwitchToTorus32(0, 32), key->lwe_key->params->alpha_min, key->lwe_key);
}


//void XOP


void XORi(vector <LweSample*> &result,
	  vector <LweSample*> &v1,
	  word8 b,
	  TFheGateBootstrappingSecretKeySet* key,
	  BaseBKeySwitchKey* ks_key){
  word8 tab_lsb[16]={};
  word8 tab_msb[16]={};
  word8 b_lsb = b%16;
  word8 b_msb = b/16;
  for(word8 i=0; i<16; i++){
    tab_lsb[i]= (i^b_lsb) &0b1111;
    tab_msb[i]= (i^b_msb) &0b1111;
  }
  deref_simple_boot(result, key, v1,  ks_key, 0, 0, tab_msb);
  deref_simple_boot(result, key, v1,  ks_key, 1, 1, tab_lsb);
}



