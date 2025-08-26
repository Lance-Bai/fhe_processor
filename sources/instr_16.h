#ifndef H_INSTR16
#define H_INSTR16
#include "tables.h"
#include "bootstrapping.h"
#include <stdlib.h>
#include <math.h>

// This file implement some 16-bit precision operations.

void ADD_16(vector<LweSample*> &result,
	    vector<LweSample*> &a,
	    vector<LweSample*> &b,
	    TFheGateBootstrappingSecretKeySet* key,
	    BaseBKeySwitchKey* ks_key);


void MULi_16(vector<LweSample*> &result,
	     vector<LweSample*> &a,
	     float b,
	     TFheGateBootstrappingSecretKeySet* key,
	     BaseBKeySwitchKey* ks_key);

// See Section 8.2
void sigmoid(vector<LweSample*> &result,
	     vector<LweSample*> &result_dec,
	     vector<LweSample*> &a,
	     vector<LweSample*> &b_dec,
	     TFheGateBootstrappingSecretKeySet* key,
	     BaseBKeySwitchKey* ks_key);


void heaviside(vector<LweSample*> &result,
	       vector<LweSample*> &result_dec,
	       vector<LweSample*> &a,
	       vector<LweSample*> &b,
	       TFheGateBootstrappingSecretKeySet* key,
	       BaseBKeySwitchKey* ks_key);


#endif
