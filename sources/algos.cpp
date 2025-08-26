#include "instr.h"
#include "instri.h"
#include "instr_16.h"
#include "tables.h"
#include "algos.h"
#include "bootstrapping.h"
#include <stdlib.h>
#include <math.h>

// This file implements the algorithms presented in Section 8.


void bubble_sort(vector <vector<LweSample*>> a,
		 word8 size,
		 TFheGateBootstrappingSecretKeySet* key,
		 BaseBKeySwitchKey* ks_key){

  vector<LweSample*>  tmp,tmp1,tmp2;
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp1.push_back(new_LweSample(key->lwe_key->params));
  tmp1.push_back(new_LweSample(key->lwe_key->params));
  tmp2.push_back(new_LweSample(key->lwe_key->params));
  tmp2.push_back(new_LweSample(key->lwe_key->params));
  
  for(int i=size-1; i>=0; i--){
    for(int j=0; j<i; j++){
      GTE(tmp, a[j], a[j+1], key, ks_key);
      lweCopy(tmp2[0], a[j+1][0], key->lwe_key->params);
      lweCopy(tmp2[1], a[j+1][1], key->lwe_key->params);
      CDUP(tmp1 , tmp[1], a[j], key, ks_key);
      NCDUP(a[j+1] , tmp[1], a[j+1], key, ks_key);
      ADDZ(a[j+1],a[j+1], tmp1, key, ks_key);

      CDUP(tmp1 , tmp[1], tmp2, key, ks_key);
      NCDUP(a[j] , tmp[1], a[j], key, ks_key);
      ADDZ(a[j],a[j], tmp1, key, ks_key);    
    }
  }
}


void maximum(vector<LweSample*> result,
	     vector<LweSample*> a,
	     word8 size,
	     TFheGateBootstrappingSecretKeySet* key,
	     BaseBKeySwitchKey* ks_key){
  vector<LweSample*> tmp, tmp2;
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp2.push_back(new_LweSample(key->lwe_key->params));
  tmp2.push_back(new_LweSample(key->lwe_key->params));
  lweCopy(tmp2[0], a[0], key->lwe_key->params);
  lweCopy(tmp2[1], a[1], key->lwe_key->params);
  for(int i=1; i<size; i++){
    lweCopy(tmp[0], a[2*i], key->lwe_key->params);
    lweCopy(tmp[1], a[2*i+1], key->lwe_key->params);
    MAX(result, tmp2, tmp, key, ks_key);
    lweCopy(tmp2[0], result[0], key->lwe_key->params);
    lweCopy(tmp2[1], result[1], key->lwe_key->params);
  }
}


void average(vector<LweSample*> result,
	     vector<LweSample*> a,
	     word8 size,
	     TFheGateBootstrappingSecretKeySet* key,
	     BaseBKeySwitchKey* ks_key){
  vector<LweSample*> tmp, tmp2;
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp2.push_back(new_LweSample(key->lwe_key->params));
  tmp2.push_back(new_LweSample(key->lwe_key->params));
  lweCopy(tmp2[0], a[0], key->lwe_key->params);
  lweCopy(tmp2[1], a[1], key->lwe_key->params);
  for(int i=1; i<size; i++){
    lweCopy(tmp[0], a[2*i], key->lwe_key->params);
    lweCopy(tmp[1], a[2*i+1], key->lwe_key->params);
    ADD(tmp2, tmp2, tmp, key, ks_key);
  }
  DIVi(tmp, tmp2, size, key, ks_key);
  lweCopy(result[0], tmp[0], key->lwe_key->params);
  lweCopy(result[1], tmp[1], key->lwe_key->params);
  DIV_DECi(tmp, tmp2, size, key, ks_key);
  lweCopy(result[2], tmp[0], key->lwe_key->params);
  lweCopy(result[3], tmp[1], key->lwe_key->params);
}



void squaresum(vector<LweSample*> result,
	       vector<LweSample*> a,
	       word8 size,
	       TFheGateBootstrappingSecretKeySet* key,
	       BaseBKeySwitchKey* ks_key){
vector<LweSample*> tmp;
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  lweCopy(tmp[0], a[0], key->lwe_key->params);
  lweCopy(tmp[1], a[1], key->lwe_key->params);
  MUL(result, tmp, tmp, key, ks_key);
  for(int i=1; i<size; i++){   
    lweCopy(tmp[0], a[2*i], key->lwe_key->params);
    lweCopy(tmp[1], a[2*i+1], key->lwe_key->params);
    MUL(tmp, tmp, tmp, key, ks_key);
    ADD(result, result, tmp, key, ks_key);
  }
}




void array_assign(vector<LweSample*> a,
		  vector<LweSample*> value,
		  vector<LweSample*> idx,
		  word8 size,
		  TFheGateBootstrappingSecretKeySet* key,
		  BaseBKeySwitchKey* ks_key){
  vector<LweSample*> tmp1,tmp2,b;
  tmp1.push_back(new_LweSample(key->lwe_key->params));
  tmp1.push_back(new_LweSample(key->lwe_key->params));
  tmp2.push_back(new_LweSample(key->lwe_key->params));
  tmp2.push_back(new_LweSample(key->lwe_key->params));
  b.push_back(new_LweSample(key->lwe_key->params));
  b.push_back(new_LweSample(key->lwe_key->params));
  for(int i=0; i<size; i++){
    lweCopy(tmp1[0], a[2*i], key->lwe_key->params);
    lweCopy(tmp1[1], a[2*i+1], key->lwe_key->params);
    EQi(b, idx, i, key, ks_key);
    CDUP(tmp2 , b[1], value, key, ks_key);
    NCDUP(tmp1 , b[1], tmp1, key, ks_key);
    ADDZ(tmp1,tmp2, tmp1, key, ks_key);   
    lweCopy(a[2*i],tmp1[0], key->lwe_key->params);
    lweCopy(a[2*i+1],tmp1[1], key->lwe_key->params);
  }
}



void perceptron_sigmoid(vector<LweSample*> &result,
			vector<LweSample*> &a,
			vector<LweSample*> &b,
			TFheGateBootstrappingSecretKeySet* key,
			BaseBKeySwitchKey* ks_key){
  float w1=0.75;
  float w2=0.125;
  vector<LweSample*> x,y, tmp;
  x.push_back(new_LweSample(key->lwe_key->params));
  x.push_back(new_LweSample(key->lwe_key->params));
  x.push_back(new_LweSample(key->lwe_key->params));
  x.push_back(new_LweSample(key->lwe_key->params));
  y.push_back(new_LweSample(key->lwe_key->params));
  y.push_back(new_LweSample(key->lwe_key->params));
  y.push_back(new_LweSample(key->lwe_key->params));
  y.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  MULi_16(x, a, w1, key, ks_key);
  MULi_16(y, b, w2, key, ks_key);
  ADD_16(tmp, x, y, key, ks_key);
  lweCopy(x[0], tmp[0], key->lwe_key->params);
  lweCopy(x[1], tmp[1], key->lwe_key->params);
  lweCopy(y[0], tmp[2], key->lwe_key->params);
  lweCopy(y[1], tmp[3], key->lwe_key->params);
  sigmoid(result, tmp, x, y, key, ks_key);
  lweCopy(result[2], tmp[0], key->lwe_key->params);
  lweCopy(result[3], tmp[1], key->lwe_key->params);
}


void perceptron_heaviside(vector<LweSample*> &result,
			  vector<LweSample*> &a,
			  vector<LweSample*> &b,
			  TFheGateBootstrappingSecretKeySet* key,
			  BaseBKeySwitchKey* ks_key){
  float w1=0.75;
  float w2=0.125;
  vector<LweSample*> x,y, tmp;
  x.push_back(new_LweSample(key->lwe_key->params));
  x.push_back(new_LweSample(key->lwe_key->params));
  x.push_back(new_LweSample(key->lwe_key->params));
  x.push_back(new_LweSample(key->lwe_key->params));
  y.push_back(new_LweSample(key->lwe_key->params));
  y.push_back(new_LweSample(key->lwe_key->params));
  y.push_back(new_LweSample(key->lwe_key->params));
  y.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  tmp.push_back(new_LweSample(key->lwe_key->params));
  MULi_16(x, a, w1, key, ks_key);
  MULi_16(y, b, w2, key, ks_key);
  ADD_16(tmp, x, y, key, ks_key);
  lweCopy(x[0], tmp[0], key->lwe_key->params);
  lweCopy(x[1], tmp[1], key->lwe_key->params);
  lweCopy(y[0], tmp[2], key->lwe_key->params);
  lweCopy(y[1], tmp[3], key->lwe_key->params);
  heaviside(result, tmp, x, y, key, ks_key); 
  lweCopy(result[2], tmp[0], key->lwe_key->params);
  lweCopy(result[3], tmp[1], key->lwe_key->params);
}



float clear_neuron_sigmoid(float a, float b){
  float w1=0.75;
  float w2=0.125;
  a = a * w1;
  b = b * w2;
  float add = a+b;
  return (1.0/(1+exp(-add)));
  
}

float clear_neuron_heaviside(float a, float b){
  float w1=0.75;
  float w2=0.125;
  a = a * w1;
  b = b * w2;
  float add = a+b;
  if(add<0) return 0.0;
  else if (add==0) return 0.5;
  else return 1.0;
}

















