#ifndef H_INSTR
#define H_INSTR

#include <stdio.h>
#include <tfhe.h>
#include <tfhe_io.h>
#include <tfhe_garbage_collector.h>

#include "base_b_keyswitchkey.h"
#include "base_b_keyswitch.h"
#include "tlwe-functions-extra.h"
#include "tlwekeyswitch.h"

using std::vector;


// Computes result = a + b mod(256)
// See Section 5.4.1
void ADD(vector<LweSample*> &result,
	 vector<LweSample*> &a,
	 vector<LweSample*> &b,
	 TFheGateBootstrappingSecretKeySet* key,
	 BaseBKeySwitchKey* ks_key);

// Computes result = a + b mod(256)
// See Section B.2.2
void ADDZ(vector<LweSample*> &result,
	  vector<LweSample*> &a,
	  vector<LweSample*> &b,
	  TFheGateBootstrappingSecretKeySet* key,
	  BaseBKeySwitchKey* ks_key);

// Computes result = a & b
// See Section B.2.1
void AND(vector <LweSample*> &result,
	 vector <LweSample*> &v1,
	 vector <LweSample*> &v2,
	 TFheGateBootstrappingSecretKeySet* key,
	 BaseBKeySwitchKey* ks_key);

// Computes result = a * b (with a the encryption of a boolean)
// See Section B.2.9
void CDUP(vector <LweSample*> &result ,
	  LweSample* a,
	  vector <LweSample*> &b,
	  TFheGateBootstrappingSecretKeySet* key,
	  BaseBKeySwitchKey* ks_key);

// Computes result = (1-a) * b (with a the encryption of a boolean)
// See Section B.2.9
void NCDUP(vector <LweSample*> &result ,
	   LweSample* a,
	   vector <LweSample*> &b,
	   TFheGateBootstrappingSecretKeySet* key,
	   BaseBKeySwitchKey* ks_key);

// Computes result = a * b + (1-a) * c (with a the encryption of a boolean)
// See Section 5.4.1
void CSEL(vector <LweSample*> &result ,
	  LweSample* a,
	  vector <LweSample*> &b,
	  vector <LweSample*> &c,
	  TFheGateBootstrappingSecretKeySet* key,
	  BaseBKeySwitchKey* ks_key);

// Computes result = a / b (Euclidean division)
// See Section 5.4.2
void DIV(vector <LweSample*> &result ,
	 vector <LweSample*> &a,
	 vector <LweSample*> &b,
	 TFheGateBootstrappingSecretKeySet* key,
	 BaseBKeySwitchKey* ks_key);

// Computes result = a / b (Euclidean division)
// See Section 5.4.2
void DIV4(vector <LweSample*> &result ,
	  vector <LweSample*> &a,
	  LweSample* b,
	  TFheGateBootstrappingSecretKeySet* key,
	  BaseBKeySwitchKey* ks_key);

// Computes result = (a == b)
// See Section B.2.7
void EQ(vector <LweSample*> &result ,
	vector <LweSample*> &a,
	vector <LweSample*> &b,
	TFheGateBootstrappingSecretKeySet* key,
	BaseBKeySwitchKey* ks_key);

// Computes result = (a > b)
// See Section B.2.7
void GT(vector <LweSample*> &result ,
	vector <LweSample*> &a,
	vector <LweSample*> &b,
        TFheGateBootstrappingSecretKeySet* key,
	BaseBKeySwitchKey* ks_key);

// Computes result = (a >= b)
// See Section B.2.7
void GTE(vector <LweSample*> &result ,
	 vector <LweSample*> &a,
	 vector <LweSample*> &b,
	 TFheGateBootstrappingSecretKeySet* key,
	 BaseBKeySwitchKey* ks_key);

// Computes result = (a < b)
// See Section B.2.7
void LT(vector <LweSample*> &result ,
	vector <LweSample*> &a,
	vector <LweSample*> &b,
	TFheGateBootstrappingSecretKeySet* key,
	BaseBKeySwitchKey* ks_key);

// Computes result = (a <= b)
// See Section B.2.7
void LTE(vector <LweSample*> &result ,
	 vector <LweSample*> &a,
	 vector <LweSample*> &b,
	 TFheGateBootstrappingSecretKeySet* key,
	 BaseBKeySwitchKey* ks_key);
	 
// Computes result = max(a,b)
// See Section B.2.4
void MAX(vector <LweSample*> &result,
	  vector <LweSample*> &a,
	  vector <LweSample*> &b,
	  TFheGateBootstrappingSecretKeySet* key,
	 BaseBKeySwitchKey* ks_key);

// Computes result = min(a,b)
// See Section B.2.4
void MIN(vector <LweSample*> &result,
	  vector <LweSample*> &a,
	  vector <LweSample*> &b,
	  TFheGateBootstrappingSecretKeySet* key,
	  BaseBKeySwitchKey* ks_key );

// Computes result = a mod(b)
// See Section B.2.6
void MOD(vector <LweSample*> &result ,
	 vector <LweSample*> &a,
	 vector<LweSample* > &b,
	 TFheGateBootstrappingSecretKeySet* key,
	 BaseBKeySwitchKey* ks_key);

// Computes result = a mod(b)
// See Section B.2.6
void MOD4(vector <LweSample*> &result ,
	  vector <LweSample*> &a,
	  LweSample* b,
	  TFheGateBootstrappingSecretKeySet* key,
	  BaseBKeySwitchKey* ks_key);

// Computes result = a * b mod(256)
// See Section B.2.3
void MUL(vector<LweSample*> &result,
	 vector<LweSample*> &a,
	 vector<LweSample*> &b,
	 TFheGateBootstrappingSecretKeySet* key,
	 BaseBKeySwitchKey* ks_key);

// Computes result = a * b (with b the encryption of a boolean)
void MULB(vector<LweSample*> &result,
	  vector<LweSample*> &a,
	  LweSample* b,
	  TFheGateBootstrappingSecretKeySet* key,
	  BaseBKeySwitchKey* ks_key);

// Computes result = a * b (the most significant byte of the result)
// See Section B.2.3
void MULM(vector<LweSample*> &result,
	  vector<LweSample*> &a,
	  vector<LweSample*> &b,
	  TFheGateBootstrappingSecretKeySet* key,
	  BaseBKeySwitchKey* ks_key);

// Computes result = a | b
// See Section B.2.1
void OR(vector <LweSample*> &result,
	vector <LweSample*> &v1,
	vector <LweSample*> &v2,
	TFheGateBootstrappingSecretKeySet* key,
	BaseBKeySwitchKey* ks_key);

// Computes result = (8*a[0]+4*a[1]+2*a[2]+a[3], 8*a[4]+4*a[5]+2*a[6]+a[7])
// See Section 6.4.2
void RC(vector<LweSample*> &result,
	vector<LweSample*> &a, 
	TFheGateBootstrappingSecretKeySet* key,
	BaseBKeySwitchKey* ks_key);

// Computes result = a << b
// See Section B.2.8
void ROL(vector <LweSample*> &result ,
	 vector <LweSample*> &a,
	 LweSample* b,
	 TFheGateBootstrappingSecretKeySet* key,
	 BaseBKeySwitchKey* ks_key);

// Computes result = a >> b
// See Section B.2.8
void ROR(vector <LweSample*> &result ,
	 vector <LweSample*> &a,
	 LweSample* b,
	 TFheGateBootstrappingSecretKeySet* key,
	 BaseBKeySwitchKey* ks_key);

// Computes result = a << b
// See Section B.2.8
void SHL(vector <LweSample*> &result ,
	 vector <LweSample*> &a,
	 LweSample* b,
	 TFheGateBootstrappingSecretKeySet* key,
	 BaseBKeySwitchKey* ks_key);

// Computes result = a >> b
// See Section B.2.8
void SHR(vector <LweSample*> &result ,
	vector <LweSample*> &a,
	LweSample* b,
	TFheGateBootstrappingSecretKeySet* key,
	 BaseBKeySwitchKey* ks_key);

// Computes result = a - b mod(256)
// See Section 5.4.1
void SUB(vector<LweSample*> &result,
	 vector<LweSample*> &a,
	 vector<LweSample*> &b,
	 TFheGateBootstrappingSecretKeySet* key,
	 BaseBKeySwitchKey* ks_key);

// Computes result = a ^ b
// See Section B.2.1
void XOR(vector <LweSample*> &result,
	 vector <LweSample*> &v1,
	 vector <LweSample*> &v2,
	 TFheGateBootstrappingSecretKeySet* key,
	 BaseBKeySwitchKey* ks_key) ;
 
#endif
