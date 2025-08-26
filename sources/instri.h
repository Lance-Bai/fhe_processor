#ifndef H_INSTRI
#define H_INSTRI

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


// Computes result = abs(a)
// See Section B.1
void ABS(vector <LweSample*> &result ,
	 vector <LweSample*> &a,
	 TFheGateBootstrappingSecretKeySet* key,
	 BaseBKeySwitchKey* ks_key);

// Computes result = a + b mod(256)
// See Section B.1
void ADDi(vector<LweSample*> &result,
	  vector<LweSample*> &a,
	  word8 b,
	  TFheGateBootstrappingSecretKeySet* key,
	  BaseBKeySwitchKey* ks_key);

// Computes result = a & b
// See Section B.3.1
void ANDi(vector <LweSample*> &result,
	  vector <LweSample*> &a,
	  word8 b,
	  TFheGateBootstrappingSecretKeySet* key,
	  BaseBKeySwitchKey* ks_key);

// Computes result = a * b (with a the encryption of a boolean)
// See Section B.3.1
void CDUPi(vector <LweSample*> &result,
	   LweSample* a,
	   word8 b,
	   TFheGateBootstrappingSecretKeySet* key,
	   BaseBKeySwitchKey* ks_key);

// Computes result = (a[0],a[1],...,a[7])
// See Section 6.4.1
void DC(vector<LweSample*> &result,
	vector<LweSample*> &a,
	TFheGateBootstrappingSecretKeySet* key,
	BaseBKeySwitchKey* ks_key);

// Computes result = a / b (Euclidean division)
// See Section B.1
void DIVi(vector <LweSample*> &result ,
	  vector <LweSample*> &a,
	  word8 b,
	  TFheGateBootstrappingSecretKeySet* key,
	  BaseBKeySwitchKey* ks_key);

// Computes result = a / b (Euclidean division)
// See Section B.1
void DIV4i(vector <LweSample*> &result ,
	   vector <LweSample*> &a,
	   word8 b,
	   TFheGateBootstrappingSecretKeySet* key,
	   BaseBKeySwitchKey* ks_key);

// Computes result = a / b (Decimal part of the result)
// See Section B.1
void DIV_DECi(vector <LweSample*> &result ,
	      vector <LweSample*> &a,
	      word8 b,
	      TFheGateBootstrappingSecretKeySet* key,
	      BaseBKeySwitchKey* ks_key);

// Computes result = (a == b)
// See Section B.4.1
void EQi(vector <LweSample*> &result ,
	 vector <LweSample*> &a,
	 word8 b,
	 TFheGateBootstrappingSecretKeySet* key,
	 BaseBKeySwitchKey* ks_key);


// Computes result = (a > b)
// See Section B.1
void GTi(vector <LweSample*> &result ,
	 vector <LweSample*> &a,
	 word8 b,
	 TFheGateBootstrappingSecretKeySet* key,
	 BaseBKeySwitchKey* ks_key);

// Computes result = (a >= b)
// See Section B.1
void GTEi(vector <LweSample*> &result ,
	  vector <LweSample*> &a,
	  word8 b,
	  TFheGateBootstrappingSecretKeySet* key,
	  BaseBKeySwitchKey* ks_key);

// Computes result = (a < b)
// See Section B.1
void LTi(vector <LweSample*> &result ,
	 vector <LweSample*> &a,
	 word8 b,
	 TFheGateBootstrappingSecretKeySet* key,
	 BaseBKeySwitchKey* ks_key);

// Computes result = (a <= b)
// See Section B.1
void LTEi(vector <LweSample*> &result ,
	  vector <LweSample*> &a,
	  word8 b,
	  TFheGateBootstrappingSecretKeySet* key,
	  BaseBKeySwitchKey* ks_key);

// Computes result = max(a,b)
// See Section B.1
void MAXi(vector <LweSample*> &result ,
	  vector <LweSample*> &a,
	  word8 b,
	  TFheGateBootstrappingSecretKeySet* key,
	  BaseBKeySwitchKey* ks_key);

// Computes result = min(a,b)
// See Section B.1
void MINi(vector <LweSample*> &result ,
	  vector <LweSample*> &a,
	  word8 b,
	  TFheGateBootstrappingSecretKeySet* key,
	  BaseBKeySwitchKey* ks_key);

// Computes result = a mod(b)
void MODi(vector <LweSample*> &result ,
	  vector <LweSample*> &a,
	  word8 b,
	  TFheGateBootstrappingSecretKeySet* key,
	  BaseBKeySwitchKey* ks_key);

// Computes result = a mod(b)
void MOD4i(vector <LweSample*> &result ,
	   vector <LweSample*> &a,
	   word8 b,
	   TFheGateBootstrappingSecretKeySet* key,
	   BaseBKeySwitchKey* ks_key);

// Computes result = a * b mod(256)
// See Section B.1
void MULi(vector<LweSample*> &result,
	  vector<LweSample*> &a,
	  word8 b,
	  TFheGateBootstrappingSecretKeySet* key,
	  BaseBKeySwitchKey* ks_key);

// Computes result = a * b (most significant byte of the result)
// See Section B.1
void MULMi(vector<LweSample*> &result,
	   vector<LweSample*> &a,
	   word8 b,
	   TFheGateBootstrappingSecretKeySet* key,
	   BaseBKeySwitchKey* ks_key);

// Computes result = neg(a)
// See Section B.1
void NEG(vector <LweSample*> &result,
	 vector <LweSample*> &a,
	 TFheGateBootstrappingSecretKeySet* key,
	 BaseBKeySwitchKey* ks_key);

// Computes result = a | b
// See Section B.1.3
void ORi(vector <LweSample*> &result,
	 vector <LweSample*> &a,
	 word8 b,
	 TFheGateBootstrappingSecretKeySet* key,
	 BaseBKeySwitchKey* ks_key);

// Computes result = a << b
// See Section B.1.2
void ROLi(vector <LweSample*> &result,
	  vector <LweSample*> &a,
	  word8 b,
	  TFheGateBootstrappingSecretKeySet* key,
	  BaseBKeySwitchKey* ks_key);

// Computes result = a >> b
// See Section B.1.2
void RORi(vector <LweSample*> &result,
	  vector <LweSample*> &a,
	  word8 b,
	  TFheGateBootstrappingSecretKeySet* key,
	  BaseBKeySwitchKey* ks_key);

// Computes result = a << b
// See Section B.1.1
void SHLi(vector <LweSample*> &result,
	  vector <LweSample*> &a,
	  word8 b,
	  TFheGateBootstrappingSecretKeySet* key,
	  BaseBKeySwitchKey* ks_key);

// Computes result = a >> b
// See Section B.1.1
void SHRi(vector <LweSample*> &result,
	  vector <LweSample*> &a,
	  word8 b,
	  TFheGateBootstrappingSecretKeySet* key,
	  BaseBKeySwitchKey* ks_key);

// Computes result = a - b mod(256)
// See Section B.1
void SUBi(vector<LweSample*> &result,
	  vector<LweSample*> &a,
	  word8 b,
	  TFheGateBootstrappingSecretKeySet* key,
	  BaseBKeySwitchKey* ks_key);

// Computes result = (a == 0)
void TZR(vector <LweSample*> &result,
	 vector <LweSample*> &a,
	 TFheGateBootstrappingSecretKeySet* key,
	 BaseBKeySwitchKey* ks_key);


//void XOP

// Computes result = a ^ b
// See Section B.1
void XORi(vector <LweSample*> &result,
	  vector <LweSample*> &a,
	  word8 b,
	  TFheGateBootstrappingSecretKeySet* key,
	  BaseBKeySwitchKey* ks_key);




#endif
