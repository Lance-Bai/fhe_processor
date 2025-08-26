#ifndef H_ALGOS
#define H_ALGOS

#include "instr.h"
#include "instri.h"
#include "tables.h"
#include "bootstrapping.h"
#include <stdlib.h>
#include <math.h>

// This file implements the algorithms presented in Section 8.

// See Section 8.1.1
void bubble_sort(vector <vector<LweSample*>> a,
		 word8 size,
		 TFheGateBootstrappingSecretKeySet* key,
		 BaseBKeySwitchKey* ks_key);

// See Section 8.1.2
void maximum(vector<LweSample*> result,
	     vector<LweSample*> a,
	     word8 size,
	     TFheGateBootstrappingSecretKeySet* key,
	     BaseBKeySwitchKey* ks_key);

// See Section 8.1.3
void average(vector<LweSample*> result,
	     vector<LweSample*> a,
	     word8 size,
	     TFheGateBootstrappingSecretKeySet* key,
	     BaseBKeySwitchKey* ks_key);

// See Section 8.1.5
void squaresum(vector<LweSample*> result,
	       vector<LweSample*> a,
	       word8 size,
	       TFheGateBootstrappingSecretKeySet* key,
	       BaseBKeySwitchKey* ks_key);

// See Section 8.1.4
void array_assign(vector<LweSample*> a,
		  vector<LweSample*> value,
		  vector<LweSample*> idx,
		  word8 size,
		  TFheGateBootstrappingSecretKeySet* key,
		  BaseBKeySwitchKey* ks_key);

// See Section 8.2
void perceptron_sigmoid(vector<LweSample*> &result,
			vector<LweSample*> &a,
			vector<LweSample*> &b,
			TFheGateBootstrappingSecretKeySet* key,
			BaseBKeySwitchKey* ks_key);

void perceptron_heaviside(vector<LweSample*> &result,
			  vector<LweSample*> &a,
			  vector<LweSample*> &b,
			  TFheGateBootstrappingSecretKeySet* key,
			  BaseBKeySwitchKey* ks_key);

// clear execution to check correctness
float clear_neuron_sigmoid(float a, float b);

// clear execution to check correctness
float clear_neuron_heaviside(float a, float b);



#endif























