#include "tables.h"
#include "bootstrapping.h"
#include "instri.h"
#include "instr.h"
#include "instr_16.h"
#include "algos.h"
#include <stdlib.h>
#include <math.h>

using namespace std;


word8 decrypt(vector<LweSample*> result, TFheGateBootstrappingSecretKeySet* key){
  int base =16;
  int32_t decr0 = lweSymDecrypt(result[0], key->lwe_key, 32);
  double decrd0 = t32tod(decr0);
  int32_t decr1 = lweSymDecrypt(result[1], key->lwe_key, 32);
  double decrd1 = t32tod(decr1);
  word8 msb= (word8)(decrd0*32+base)%base*base;
  word8 lsb= (word8)(decrd1*32+base)%base;

  return msb+lsb;
}


int decrypt_sign(vector<LweSample*> result, TFheGateBootstrappingSecretKeySet* key){
  int base =16;
  int32_t decr0 = lweSymDecrypt(result[0], key->lwe_key, 32);
  double decrd0 = t32tod(decr0);
  int32_t decr1 = lweSymDecrypt(result[1], key->lwe_key, 32);
  double decrd1 = t32tod(decr1);
  word8 msb= (word8)(decrd0*32+base)%base*base;
  word8 lsb= (word8)(decrd1*32+base)%base;

  if(msb+lsb >= 128){// le premier bit du chiffré est 1, id c'est un chiffré négatif
    return (int) (msb+lsb)-256;
  }
  
  return msb+lsb;
}


float decrypt_dec(vector<LweSample*> result, TFheGateBootstrappingSecretKeySet* key){
  int base =16;
  int32_t decr0 = lweSymDecrypt(result[0], key->lwe_key, 32);
  double decrd0 = t32tod(decr0);
  int32_t decr1 = lweSymDecrypt(result[1], key->lwe_key, 32);
  double decrd1 = t32tod(decr1);
  word8 msb= (word8)(decrd0*32+base)%base*base;
  word8 lsb= (word8)(decrd1*32+base)%base;

  return (msb+lsb)/256.0;
}


void test_16(TFheGateBootstrappingSecretKeySet* key, BaseBKeySwitchKey* ks_key, double alpha){
  float a = 0.12345;
  float b = 0.06789;
  //float a = 1.0;
  //float b = 0.750;
  word8 a_msb = (word8) floor(a)/16;
  word8 a_lsb = (word8) floor(a)%16;
  word8 a_dec_msb =(word8) ((a-floor(a))*256)/16;
  word8 a_dec_lsb =(word8) ((a-floor(a))*256)%16;
  
  word8 b_msb = (word8) floor(b)/16;
  word8 b_lsb = (word8) floor(b)%16;
  word8 b_dec_msb =(word8) ((b-floor(b))*256)/16;
  word8 b_dec_lsb = (word8) ((b-floor(b))*256)%16;

  vector<LweSample*> ca;
  vector<LweSample*> cb;
  ca.push_back(new_LweSample(key->lwe_key->params));
  lweSymEncrypt(ca[0], modSwitchToTorus32(a_msb, 32), alpha, key->lwe_key);
  ca.push_back(new_LweSample(key->lwe_key->params));
  lweSymEncrypt(ca[1], modSwitchToTorus32(a_lsb, 32), alpha, key->lwe_key);
  ca.push_back(new_LweSample(key->lwe_key->params));
  lweSymEncrypt(ca[2], modSwitchToTorus32(a_dec_msb, 32), alpha, key->lwe_key);
  ca.push_back(new_LweSample(key->lwe_key->params));
  lweSymEncrypt(ca[3], modSwitchToTorus32(a_dec_lsb, 32), alpha, key->lwe_key);
  
  cb.push_back(new_LweSample(key->lwe_key->params));
  lweSymEncrypt(cb[0], modSwitchToTorus32(b_msb, 32), alpha, key->lwe_key);
  cb.push_back(new_LweSample(key->lwe_key->params));
  lweSymEncrypt(cb[1], modSwitchToTorus32(b_lsb, 32), alpha, key->lwe_key);
  cb.push_back(new_LweSample(key->lwe_key->params));
  lweSymEncrypt(cb[2], modSwitchToTorus32(b_dec_msb, 32), alpha, key->lwe_key);
  cb.push_back(new_LweSample(key->lwe_key->params));
  lweSymEncrypt(cb[3], modSwitchToTorus32(b_dec_lsb, 32), alpha, key->lwe_key);
  
  vector<LweSample*> result, result_bis;
  result.push_back(new_LweSample(key->lwe_key->params));
  result.push_back(new_LweSample(key->lwe_key->params));
  result.push_back(new_LweSample(key->lwe_key->params));
  result.push_back(new_LweSample(key->lwe_key->params));
  result_bis.push_back(new_LweSample(key->lwe_key->params));
  result_bis.push_back(new_LweSample(key->lwe_key->params));
  
  printf("Decimal Addition of two encrypted 16-bit values\n");
  struct timespec begin, end; 
  clock_gettime(CLOCK_REALTIME, &begin);
  ADD_16(result, ca, cb, key, ks_key);
  clock_gettime(CLOCK_REALTIME, &end);
  long seconds = end.tv_sec - begin.tv_sec;
  long nanoseconds = end.tv_nsec - begin.tv_nsec;
  double elapsed = seconds + nanoseconds*1e-9;

  word8 dec = decrypt(result, key);
  lweCopy(result_bis[0], result[2], key->lwe_key->params);
  lweCopy(result_bis[1], result[3], key->lwe_key->params);
  float dec_f = decrypt_dec(result_bis, key);
  printf("  %f + %f = %f (should be close to %f)\n", a, b, dec+dec_f, a+b);
  printf("  timing : %.5f\n\n", elapsed);

  printf("MULi_16\n");
  clock_gettime(CLOCK_REALTIME, &begin);
  MULi_16(result, cb, a, key, ks_key);
  clock_gettime(CLOCK_REALTIME, &end);
  seconds = end.tv_sec - begin.tv_sec;
  nanoseconds = end.tv_nsec - begin.tv_nsec;
  elapsed = seconds + nanoseconds*1e-9;
  dec = decrypt(result, key);
  lweCopy(result_bis[0], result[2], key->lwe_key->params);
  lweCopy(result_bis[1], result[3], key->lwe_key->params);
  dec_f = decrypt_dec(result_bis, key);
  printf("  %f * %f = %f (should be close to %f)\n", b, a, dec+dec_f, a*b);
  printf("  timing : %.5f\n\n", elapsed);
  
  printf("Neuron evaluation with sigmoid\n");
  clock_gettime(CLOCK_REALTIME, &begin);
  perceptron_sigmoid(result, ca, cb, key, ks_key);
  clock_gettime(CLOCK_REALTIME, &end);
  seconds = end.tv_sec - begin.tv_sec;
  nanoseconds = end.tv_nsec - begin.tv_nsec;
  elapsed = seconds + nanoseconds*1e-9;
  dec = decrypt(result, key);
  lweCopy(result_bis[0], result[2], key->lwe_key->params);
  lweCopy(result_bis[1], result[3], key->lwe_key->params);
  dec_f = decrypt_dec(result_bis, key);
  printf("  Neuron(%f, %f) = sigmoid(%f*0.75 + %f*0.125) = %f (should be close to %f)\n", a, b, a, b, dec+dec_f, clear_neuron_sigmoid(a,b));
  printf("  timing : %.5f\n\n", elapsed);

  printf("Neuron evaluation with Heaviside\n");
  clock_gettime(CLOCK_REALTIME, &begin);
  perceptron_heaviside(result, ca, cb, key, ks_key);
  clock_gettime(CLOCK_REALTIME, &end);
  seconds = end.tv_sec - begin.tv_sec;
  nanoseconds = end.tv_nsec - begin.tv_nsec;
  elapsed = seconds + nanoseconds*1e-9;
  dec = decrypt(result, key);
  lweCopy(result_bis[0], result[2], key->lwe_key->params);
  lweCopy(result_bis[1], result[3], key->lwe_key->params);
  dec_f = decrypt_dec(result_bis, key);
  printf("  Neuron(%f, %f) = heaviside(%f*0.75 + %f*0.125) = %f (should be close to %f)\n", a, b, a, b, dec+dec_f, clear_neuron_heaviside(a,b));
    printf("  timing : %.5f\n", elapsed);
}




int main(int argc, char *argv[]){
  if(argc<3){
    printf("Please insert at least two 8-bit numbers\n");
    return 0;
  }
  word8 tab_clear[argc-1];
  for(int i=0; i<argc-1; i++)
    tab_clear[i] = atoi(argv[i+1]);
  word8 a =   atoi(argv[1]);
  word8 b =   atoi(argv[2]);

  const int minimum_lambda = 110;
  static const int32_t N = 2048;
  static const int32_t k = 1;
  static const int32_t n = 1024;
  static const int32_t bk_l = 3;
  static const int32_t bk_Bgbit = 8;
  static const int32_t ks_basebit = 10;
  static const int32_t ks_length = 2;
  static const double ks_stdev = pow(5.6,-8);//standard deviation
  static const double bk_stdev = pow(9.6,-11);//standard deviation
  static const double max_stdev = 0.012467; //max standard deviation for a 1/4 msg space
  LweParams *params_in = new_LweParams(n, ks_stdev, max_stdev);
  TLweParams *params_accum = new_TLweParams(N, k, bk_stdev, max_stdev);
  TGswParams *params_bk = new_TGswParams(bk_l, bk_Bgbit, params_accum);

  TfheGarbageCollector::register_param(params_in);
  TfheGarbageCollector::register_param(params_accum);
  TfheGarbageCollector::register_param(params_bk);
  printf("Key Generation in progress... (it should take about a minute)\n");
  TFheGateBootstrappingParameterSet* params = new TFheGateBootstrappingParameterSet(ks_length, ks_basebit, params_in, params_bk);
  uint32_t seed[] = {314, 1592, 657, 26363, 394, 4958, 4059, 3845};
  tfhe_random_generator_setSeed(seed, 8);
  TFheGateBootstrappingSecretKeySet* key = new_random_gate_bootstrapping_secret_keyset(params);
  const LweKey * k_in = key->lwe_key;
  const TLweKey * k_out = &key->tgsw_key->tlwe_key;
  BaseBKeySwitchKey* ks_key = new_BaseBKeySwitchKey( key->lwe_key->params->n, 2, 10, 16, key->cloud.bk->accum_params);
  BaseBExtra::CreateKeySwitchKey(ks_key, k_in, k_out);

  printf("Key Generation is over!\n");
  double alpha = key->lwe_key->params->alpha_min;
  word8 base=16;

  word8 a_msb = (word8) a/16;
  word8 a_lsb = (word8) a%16;
  word8 b_msb = (word8) b/16;
  word8 b_lsb = (word8) b%16;

  vector<LweSample*> ca;
  vector<LweSample*> cb;
  ca.push_back(new_LweSample(key->lwe_key->params));
  lweSymEncrypt(ca[0], modSwitchToTorus32(a_msb, 32), alpha, key->lwe_key);
  ca.push_back(new_LweSample(key->lwe_key->params));
  lweSymEncrypt(ca[1], modSwitchToTorus32(a_lsb, 32), alpha, key->lwe_key);
  cb.push_back(new_LweSample(key->lwe_key->params));
  lweSymEncrypt(cb[0], modSwitchToTorus32(b_msb, 32), alpha, key->lwe_key);
  cb.push_back(new_LweSample(key->lwe_key->params));
  lweSymEncrypt(cb[1], modSwitchToTorus32(b_lsb, 32), alpha, key->lwe_key);
  vector<LweSample*> zero;
  zero.push_back(new_LweSample(key->lwe_key->params));
  lweSymEncrypt(zero[0], modSwitchToTorus32(0, 32), alpha, key->lwe_key);
  zero.push_back(new_LweSample(key->lwe_key->params));
  lweSymEncrypt(zero[1], modSwitchToTorus32(0, 32), alpha, key->lwe_key);
  vector<LweSample*> one;
  one.push_back(new_LweSample(key->lwe_key->params));
  lweSymEncrypt(one[0], modSwitchToTorus32(1, 32), alpha, key->lwe_key);
  one.push_back(new_LweSample(key->lwe_key->params));
  lweSymEncrypt(one[1], modSwitchToTorus32(1, 32), alpha, key->lwe_key);

  vector<LweSample*> result, result_bis;
  result.push_back(new_LweSample(key->lwe_key->params));
  result.push_back(new_LweSample(key->lwe_key->params));
  result_bis.push_back(new_LweSample(key->lwe_key->params));
  result_bis.push_back(new_LweSample(key->lwe_key->params));

  struct timespec begin, end;
  long seconds, nanoseconds;
  double elapsed, acc;
  word8 dec;
  
  
  printf("Additions\n");
  clock_gettime(CLOCK_REALTIME, &begin);
  ADD(result, ca, cb, key, ks_key);
  clock_gettime(CLOCK_REALTIME, &end);
  seconds = end.tv_sec - begin.tv_sec;
  nanoseconds = end.tv_nsec - begin.tv_nsec;
  elapsed = seconds + nanoseconds*1e-9;

  dec = decrypt(result, key);
  printf("  ADD: %d + %d = %d\n", a, b, dec);
  printf("  timing: %.5f\n", elapsed);

  
  clock_gettime(CLOCK_REALTIME, &begin);
  ADDi(result, ca, b, key, ks_key);
  clock_gettime(CLOCK_REALTIME, &end);
  seconds = end.tv_sec - begin.tv_sec;
  nanoseconds = end.tv_nsec - begin.tv_nsec;
  elapsed = seconds + nanoseconds*1e-9;
  dec = decrypt(result, key);
  printf("  ADDi: %d + %d = %d\n", a, b, dec);
  printf("  timings : %.5f\n", elapsed);

  
  clock_gettime(CLOCK_REALTIME, &begin);
  ADDZ(result, ca, zero, key, ks_key);
  clock_gettime(CLOCK_REALTIME, &end);
  seconds = end.tv_sec - begin.tv_sec;
  nanoseconds = end.tv_nsec - begin.tv_nsec;
  elapsed = seconds + nanoseconds*1e-9;
  dec = decrypt(result, key);
  printf("  ADDZ: %d + 0 = %d\n", a, dec);
  printf("  timing: %.5f\n\n", elapsed);

  
  printf("Multiplications\n");
  clock_gettime(CLOCK_REALTIME, &begin);
  MUL(result, ca, cb, key, ks_key);
  clock_gettime(CLOCK_REALTIME, &end);
  seconds = end.tv_sec - begin.tv_sec;
  nanoseconds = end.tv_nsec - begin.tv_nsec;
  elapsed = seconds + nanoseconds*1e-9;
  dec = decrypt(result, key);
  printf("  MUL: %d * %d = %d\n", a, b, dec);
  printf("  timing: %.5f\n", elapsed);


  clock_gettime(CLOCK_REALTIME, &begin);
  MULi(result, ca, b, key, ks_key);
  clock_gettime(CLOCK_REALTIME, &end);
  seconds = end.tv_sec - begin.tv_sec;
  nanoseconds = end.tv_nsec - begin.tv_nsec;
  elapsed = seconds + nanoseconds*1e-9;
  dec = decrypt(result, key);
  printf("  MULi: %d * %d = %d\n", a, b, dec);
  printf("  timing: %.5f\n", elapsed);
 
  
  clock_gettime(CLOCK_REALTIME, &begin);
  MULM(result, ca, cb, key, ks_key);
  clock_gettime(CLOCK_REALTIME, &end);
  seconds = end.tv_sec - begin.tv_sec;
  nanoseconds = end.tv_nsec - begin.tv_nsec;
  elapsed = seconds + nanoseconds*1e-9;
  dec = decrypt(result, key);
  printf("  MULM: %d * %d = %d\n", a, b, dec);
  printf("  timings : %.5f\n", elapsed);
  
  clock_gettime(CLOCK_REALTIME, &begin);
  MULMi(result, ca, b, key, ks_key);
  clock_gettime(CLOCK_REALTIME, &end);
  seconds = end.tv_sec - begin.tv_sec;
  nanoseconds = end.tv_nsec - begin.tv_nsec;
  elapsed = seconds + nanoseconds*1e-9;
  dec = decrypt(result, key);
  printf("  MULMi: %d * %d = %d\n", a, b, dec);
  printf("  timings : %.5f\n\n", elapsed);
 
    
  printf("Minimum\n");
  clock_gettime(CLOCK_REALTIME, &begin);
  MIN(result, ca, cb, key, ks_key);
  clock_gettime(CLOCK_REALTIME, &end);
  seconds = end.tv_sec - begin.tv_sec;
  nanoseconds = end.tv_nsec - begin.tv_nsec;
  elapsed = seconds + nanoseconds*1e-9;
  dec = decrypt(result, key);
  printf("  MIN(%d, %d) = %d\n", a, b, dec);
  printf("  timing: %.5f\n", elapsed);

  clock_gettime(CLOCK_REALTIME, &begin);
  MINi(result, ca, b, key, ks_key);
  clock_gettime(CLOCK_REALTIME, &end);
  seconds = end.tv_sec - begin.tv_sec;
  nanoseconds = end.tv_nsec - begin.tv_nsec;
  elapsed = seconds + nanoseconds*1e-9;
  dec = decrypt(result, key);
  printf("  MINi(%d, %d) = %d\n", a, b, dec);
  printf("  timing: %.5f\n\n", elapsed);
 
  
  printf("Maximum\n");
  clock_gettime(CLOCK_REALTIME, &begin);
  MAX(result, ca, cb, key, ks_key);
  clock_gettime(CLOCK_REALTIME, &end);
  seconds = end.tv_sec - begin.tv_sec;
  nanoseconds = end.tv_nsec - begin.tv_nsec;
  elapsed = seconds + nanoseconds*1e-9;
  dec = decrypt(result, key);
  printf("  MAX(%d, %d) = %d\n", a, b, dec);
  printf("  timing: %.5f\n", elapsed);

  clock_gettime(CLOCK_REALTIME, &begin);
  MAXi(result, ca, b, key, ks_key);
  clock_gettime(CLOCK_REALTIME, &end);
  seconds = end.tv_sec - begin.tv_sec;
  nanoseconds = end.tv_nsec - begin.tv_nsec;
  elapsed = seconds + nanoseconds*1e-9;
  dec = decrypt(result, key);
  printf("  MAXi(%d, %d) = %d\n", a, b, dec);
  printf("  timing: %.5f\n\n", elapsed);
  
  printf("Subtraction\n");
  clock_gettime(CLOCK_REALTIME, &begin);
  SUB(result, ca, cb, key, ks_key);
  clock_gettime(CLOCK_REALTIME, &end);
  seconds = end.tv_sec - begin.tv_sec;
  nanoseconds = end.tv_nsec - begin.tv_nsec;
  elapsed = seconds + nanoseconds*1e-9;
  dec = decrypt(result, key);
  printf("  SUB: %d - %d = %d\n", a, b, dec);
  printf("  timing: %.5f\n", elapsed);

  clock_gettime(CLOCK_REALTIME, &begin);
  SUBi(result, ca, b, key, ks_key);
  clock_gettime(CLOCK_REALTIME, &end);
  seconds = end.tv_sec - begin.tv_sec;
  nanoseconds = end.tv_nsec - begin.tv_nsec;
  elapsed = seconds + nanoseconds*1e-9;
  dec = decrypt(result, key);
  printf("  SUBi: %d - %d = %d\n", a, b, dec);
  printf("  timing: %.5f\n\n", elapsed);


  printf("XOR\n");
  clock_gettime(CLOCK_REALTIME, &begin);
  XOR(result, ca, cb, key, ks_key);
  clock_gettime(CLOCK_REALTIME, &end);
  seconds = end.tv_sec - begin.tv_sec;
  nanoseconds = end.tv_nsec - begin.tv_nsec;
  elapsed = seconds + nanoseconds*1e-9;
  dec = decrypt(result, key);
  printf("  XOR: %d XOR %d = %d\n", a, b, dec);
  printf("  timing: %.5f\n", elapsed);

  clock_gettime(CLOCK_REALTIME, &begin);
  XORi(result, ca, b, key, ks_key);
  clock_gettime(CLOCK_REALTIME, &end);
  seconds = end.tv_sec - begin.tv_sec;
  nanoseconds = end.tv_nsec - begin.tv_nsec;
  elapsed = seconds + nanoseconds*1e-9;
  dec = decrypt(result, key);
  printf("  XORi: %d XOR %d = %d\n", a, b, dec);
  printf("  timing: %.5f\n\n", elapsed);

  printf("AND\n");
  clock_gettime(CLOCK_REALTIME, &begin);
  AND(result, ca, cb, key, ks_key);
  clock_gettime(CLOCK_REALTIME, &end);
  seconds = end.tv_sec - begin.tv_sec;
  nanoseconds = end.tv_nsec - begin.tv_nsec;
  elapsed = seconds + nanoseconds*1e-9;
  dec = decrypt(result, key);
  printf("  AND: %d AND %d = %d\n", a, b, dec);
  printf("  timing: %.5f\n", elapsed);

  clock_gettime(CLOCK_REALTIME, &begin);
  ANDi(result, ca, b, key, ks_key);
  clock_gettime(CLOCK_REALTIME, &end);
  seconds = end.tv_sec - begin.tv_sec;
  nanoseconds = end.tv_nsec - begin.tv_nsec;
  elapsed = seconds + nanoseconds*1e-9;
  dec = decrypt(result, key);
  printf("  ANDi: %d AND %d = %d\n", a, b, dec);
  printf("  timing: %.5f\n\n", elapsed);

  printf("OR\n");
  clock_gettime(CLOCK_REALTIME, &begin);
  OR(result, ca, cb, key, ks_key);
  clock_gettime(CLOCK_REALTIME, &end);
  seconds = end.tv_sec - begin.tv_sec;
  nanoseconds = end.tv_nsec - begin.tv_nsec;
  elapsed = seconds + nanoseconds*1e-9;
  dec = decrypt(result, key);
  printf("  ORi: %d OR %d = %d\n", a, b, dec);
  printf("  timing: %.5f\n", elapsed);

  clock_gettime(CLOCK_REALTIME, &begin);
  ORi(result, ca, b, key, ks_key);
  clock_gettime(CLOCK_REALTIME, &end);
  seconds = end.tv_sec - begin.tv_sec;
  nanoseconds = end.tv_nsec - begin.tv_nsec;
  elapsed = seconds + nanoseconds*1e-9;
  dec = decrypt(result, key);
  printf("  ORi: %d OR %d = %d\n", a, b, dec);
  printf("  timing: %.5f\n\n", elapsed);

  
  printf("Left shift\n");
  clock_gettime(CLOCK_REALTIME, &begin);
  SHLi(result, ca, 3, key, ks_key);
  clock_gettime(CLOCK_REALTIME, &end);
  seconds = end.tv_sec - begin.tv_sec;
  nanoseconds = end.tv_nsec - begin.tv_nsec;
  elapsed = seconds + nanoseconds*1e-9;
  dec = decrypt(result, key);
  printf("  SHLi: %d<<%d = %d\n", a, 3, dec);
  printf("  timing: %.5f\n", elapsed);


  clock_gettime(CLOCK_REALTIME, &begin);
  SHL(result, ca, cb[1], key, ks_key);
  clock_gettime(CLOCK_REALTIME, &end);
  seconds = end.tv_sec - begin.tv_sec;
  nanoseconds = end.tv_nsec - begin.tv_nsec;
  elapsed = seconds + nanoseconds*1e-9;
  dec = decrypt(result, key);
  printf("  SHL: %d<<%d = %d\n", a, b_lsb, dec);
  printf("  timing: %.5f\n", elapsed);
  
  printf("Left rotation\n");
  clock_gettime(CLOCK_REALTIME, &begin);
  ROL(result, ca, cb[0], key, ks_key);
  clock_gettime(CLOCK_REALTIME, &end);
  seconds = end.tv_sec - begin.tv_sec;
  nanoseconds = end.tv_nsec - begin.tv_nsec;
  elapsed = seconds + nanoseconds*1e-9;
  dec = decrypt(result, key);
  printf("  ROL: %d<<<%d = %d\n", a, b_msb, dec);
  printf("  timing: %.5f\n", elapsed);
  
  clock_gettime(CLOCK_REALTIME, &begin);
  ROLi(result, ca, b_msb, key, ks_key);
  clock_gettime(CLOCK_REALTIME, &end);
  seconds = end.tv_sec - begin.tv_sec;
  nanoseconds = end.tv_nsec - begin.tv_nsec;
  elapsed = seconds + nanoseconds*1e-9;
  dec = decrypt(result, key);
  printf("  ROLi: %d<<<%d = %d\n", a, b_msb, dec);
  printf("  timing: %.5f\n\n", elapsed);

  printf("Right shift\n");
  clock_gettime(CLOCK_REALTIME, &begin);
  SHRi(result, ca, 3, key, ks_key);
  clock_gettime(CLOCK_REALTIME, &end);
  seconds = end.tv_sec - begin.tv_sec;
  nanoseconds = end.tv_nsec - begin.tv_nsec;
  elapsed = seconds + nanoseconds*1e-9;
  dec = decrypt(result, key);
  printf("  SHRi: %d>>%d = %d \n", a, 3, dec);
  printf("  timing: %.5f\n", elapsed);
  
  clock_gettime(CLOCK_REALTIME, &begin);
  SHR(result, ca, cb[0], key, ks_key);
  clock_gettime(CLOCK_REALTIME, &end);
  seconds = end.tv_sec - begin.tv_sec;
  nanoseconds = end.tv_nsec - begin.tv_nsec;
  elapsed = seconds + nanoseconds*1e-9;
  dec = decrypt(result, key);
  printf("  SHR: %d>>%d = %d\n", a, b_msb, dec);
  printf("  timing: %.5f\n\n", elapsed);
  
  printf("Right rotation\n");
  clock_gettime(CLOCK_REALTIME, &begin);
  ROR(result, ca, cb[0], key, ks_key);
  clock_gettime(CLOCK_REALTIME, &end);
  seconds = end.tv_sec - begin.tv_sec;
  nanoseconds = end.tv_nsec - begin.tv_nsec;
  elapsed = seconds + nanoseconds*1e-9;
  dec = decrypt(result, key);
  printf("  ROR: %d>>>%d = %d\n", a, b_msb, dec);
  printf("  timing: %.5f\n", elapsed);

  clock_gettime(CLOCK_REALTIME, &begin);
  RORi(result, ca, b_msb, key, ks_key);
  clock_gettime(CLOCK_REALTIME, &end);
  seconds = end.tv_sec - begin.tv_sec;
  nanoseconds = end.tv_nsec - begin.tv_nsec;
  elapsed = seconds + nanoseconds*1e-9;
  dec = decrypt(result, key);
  printf("  RORi: %d>>>%d = %d\n", a, b_msb, dec);
  printf("  timing: %.5f\n\n", elapsed);

  if(b_lsb!=0){
  printf("DIV4\n");
  clock_gettime(CLOCK_REALTIME, &begin);
  DIV4(result, ca, cb[1], key, ks_key);
  clock_gettime(CLOCK_REALTIME, &end);
  seconds = end.tv_sec - begin.tv_sec;
  nanoseconds = end.tv_nsec - begin.tv_nsec;
  elapsed = seconds + nanoseconds*1e-9;
  dec = decrypt(result, key);
  printf("  DIV4: %d/%d = %d (should be %d)\n", a, b_lsb, dec, a/b_lsb);
  printf("  timing: %.5f\n", elapsed);
  }
  if(b_msb!=0){
  clock_gettime(CLOCK_REALTIME, &begin);
  DIV4(result, ca, cb[0], key, ks_key);
  clock_gettime(CLOCK_REALTIME, &end);
  seconds = end.tv_sec - begin.tv_sec;
  nanoseconds = end.tv_nsec - begin.tv_nsec;
  elapsed = seconds + nanoseconds*1e-9;
  dec = decrypt(result, key);
  printf("  DIV4: %d/%d = %d (should be %d)\n", a, b_msb, dec, a/b_msb);
  printf("  timing: %.5f\n", elapsed);
  }
  if(b_lsb!=0){
  clock_gettime(CLOCK_REALTIME, &begin);
  DIV4i(result, ca, b_lsb, key, ks_key);
  clock_gettime(CLOCK_REALTIME, &end);
  seconds = end.tv_sec - begin.tv_sec;
  nanoseconds = end.tv_nsec - begin.tv_nsec;
  elapsed = seconds + nanoseconds*1e-9;
  dec = decrypt(result, key);
  printf("  DIV4i: %d/%d = %d (should be %d)\n", a, b_lsb, dec, a/b_lsb);
  printf("  timing: %.5f\n\n", elapsed);
  }
  if(b_msb!=0){
  clock_gettime(CLOCK_REALTIME, &begin);
  DIV4i(result, ca, b_msb, key, ks_key);
  clock_gettime(CLOCK_REALTIME, &end);
  seconds = end.tv_sec - begin.tv_sec;
  nanoseconds = end.tv_nsec - begin.tv_nsec;
  elapsed = seconds + nanoseconds*1e-9;
  dec = decrypt(result, key);
  printf("  DIV4i: %d/%d = %d (sould be %d)\n", a, b_msb, dec, a/b_msb);
  printf("  timing: %.5f\n\n", elapsed);
  }
  
  printf("Division\n");
  clock_gettime(CLOCK_REALTIME, &begin);
  DIV(result, ca, cb, key, ks_key);
  clock_gettime(CLOCK_REALTIME, &end);
  seconds = end.tv_sec - begin.tv_sec;
  nanoseconds = end.tv_nsec - begin.tv_nsec;
  elapsed = seconds + nanoseconds*1e-9;
  dec = decrypt(result, key);
  printf("  DIV: %d/%d = %d (should be %d)\n", a, b, dec, a/b);
  printf("  timing: %.5f\n", elapsed);

  clock_gettime(CLOCK_REALTIME, &begin);
  DIV(result, cb, ca, key, ks_key);
  clock_gettime(CLOCK_REALTIME, &end);
  seconds = end.tv_sec - begin.tv_sec;
  nanoseconds = end.tv_nsec - begin.tv_nsec;
  elapsed = seconds + nanoseconds*1e-9;
  dec = decrypt(result, key);
  printf("  DIV: %d/%d = %d (should be %d)\n", b, a, dec, b/a);
  printf("  timing: %.5f\n", elapsed);

  clock_gettime(CLOCK_REALTIME, &begin);
  DIVi(result, ca, b, key, ks_key);
  clock_gettime(CLOCK_REALTIME, &end);
  seconds = end.tv_sec - begin.tv_sec;
  nanoseconds = end.tv_nsec - begin.tv_nsec;
  elapsed = seconds + nanoseconds*1e-9;
  dec = decrypt(result, key);
  printf("  DIVi: %d/%d = %d (should be %d)\n", a, b, dec, a/b);
  printf("  timing: %.5f\n", elapsed);
  if(b_lsb!=0){
  clock_gettime(CLOCK_REALTIME, &begin);
  DIVi(result, ca, b_lsb, key, ks_key);
  clock_gettime(CLOCK_REALTIME, &end);
  seconds = end.tv_sec - begin.tv_sec;
  nanoseconds = end.tv_nsec - begin.tv_nsec;
  elapsed = seconds + nanoseconds*1e-9;
  dec = decrypt(result, key);
  printf("  DIVi: %d/%d = %d (should be %d)\n", a, b_lsb, dec, a/b_lsb);
  printf("  timing: %.5f\n\n", elapsed);
  }
  
  printf("Modulo \n");
  clock_gettime(CLOCK_REALTIME, &begin);
  MOD(result, ca, cb, key, ks_key);
  clock_gettime(CLOCK_REALTIME, &end);
  seconds = end.tv_sec - begin.tv_sec;
  nanoseconds = end.tv_nsec - begin.tv_nsec;
  elapsed = seconds + nanoseconds*1e-9;
  dec = decrypt(result, key);
  printf("  MOD: %d mod(%d) = %d (should be %d)\n", a, b, dec, a%b);
  printf("  timing: %.5f\n", elapsed);

  clock_gettime(CLOCK_REALTIME, &begin);
  MODi(result, ca, b, key, ks_key);
  clock_gettime(CLOCK_REALTIME, &end);
  seconds = end.tv_sec - begin.tv_sec;
  nanoseconds = end.tv_nsec - begin.tv_nsec;
  elapsed = seconds + nanoseconds*1e-9;
  dec = decrypt(result, key);
  printf("  MODi: %d mod(%d) = %d (should be %d)\n", a, b, dec, a%b);
  printf("  timing: %.5f\n\n", elapsed);

  if(b_lsb!=0){
  clock_gettime(CLOCK_REALTIME, &begin);
  MOD4(result, ca, cb[1], key, ks_key);
  clock_gettime(CLOCK_REALTIME, &end);
  seconds = end.tv_sec - begin.tv_sec;
  nanoseconds = end.tv_nsec - begin.tv_nsec;
  elapsed = seconds + nanoseconds*1e-9;
  dec = decrypt(result, key);
  printf("  MOD4: %d mod(%d) = %d (should be %d)\n", a, b_lsb, dec, a%b_lsb);
  printf("  timing: %.5f\n", elapsed);

  clock_gettime(CLOCK_REALTIME, &begin);
  MOD4i(result, ca, b_lsb, key, ks_key);
  clock_gettime(CLOCK_REALTIME, &end);
  seconds = end.tv_sec - begin.tv_sec;
  nanoseconds = end.tv_nsec - begin.tv_nsec;
  elapsed = seconds + nanoseconds*1e-9;
  dec = decrypt(result, key);
  printf("  MOD4i: %d mod(%d) = %d (should be %d)\n", a, b_lsb, dec, a%b_lsb);
  printf("  timing: %.5f\n\n", elapsed);
  }
  
  printf("Test zero\n");
  clock_gettime(CLOCK_REALTIME, &begin);
  TZR(result, ca, key, ks_key);
  clock_gettime(CLOCK_REALTIME, &end);
  seconds = end.tv_sec - begin.tv_sec;
  nanoseconds = end.tv_nsec - begin.tv_nsec;
  elapsed = seconds + nanoseconds*1e-9;
  dec = decrypt(result, key);
  printf("  TZR : %d =? 0 ==> %d\n", a, dec);
  printf("  timing: %.5f\n", elapsed);

  clock_gettime(CLOCK_REALTIME, &begin);
  TZR(result, zero, key, ks_key);
  clock_gettime(CLOCK_REALTIME, &end);
  seconds = end.tv_sec - begin.tv_sec;
  nanoseconds = end.tv_nsec - begin.tv_nsec;
  elapsed = seconds + nanoseconds*1e-9;
  dec = decrypt(result, key);
  printf("  TZR : %d =? 0 ==> %d\n", 0, dec);
  printf("  timing: %.5f\n\n", elapsed);
  
  printf("Equality test\n");
  clock_gettime(CLOCK_REALTIME, &begin);
  EQi(result, ca, b, key, ks_key);
  clock_gettime(CLOCK_REALTIME, &end);
  seconds = end.tv_sec - begin.tv_sec;
  nanoseconds = end.tv_nsec - begin.tv_nsec;
  elapsed = seconds + nanoseconds*1e-9;
  dec = decrypt(result, key);
  printf("  EQi: %d =? %d ==> %d\n", a, b, dec);
  printf("  timing: %.5f\n", elapsed);

  clock_gettime(CLOCK_REALTIME, &begin);
  EQi(result, ca, a, key, ks_key);
  clock_gettime(CLOCK_REALTIME, &end);
  seconds = end.tv_sec - begin.tv_sec;
  nanoseconds = end.tv_nsec - begin.tv_nsec;
  elapsed = seconds + nanoseconds*1e-9;
  dec = decrypt(result, key);
  printf("  EQi: %d =? %d ==> %d\n", a, a, dec);
  printf("  timing: %.5f\n", elapsed);

  clock_gettime(CLOCK_REALTIME, &begin);
  EQ(result, ca, cb, key, ks_key);
  clock_gettime(CLOCK_REALTIME, &end);
  seconds = end.tv_sec - begin.tv_sec;
  nanoseconds = end.tv_nsec - begin.tv_nsec;
  elapsed = seconds + nanoseconds*1e-9;
  dec = decrypt(result, key);
  printf("  EQ: %d =? %d ==> %d\n", a, b, dec);
  printf("  timing: %.5f\n", elapsed);


  clock_gettime(CLOCK_REALTIME, &begin);
  EQ(result, ca, ca, key, ks_key);
  clock_gettime(CLOCK_REALTIME, &end);
  seconds = end.tv_sec - begin.tv_sec;
  nanoseconds = end.tv_nsec - begin.tv_nsec;
  elapsed = seconds + nanoseconds*1e-9;
  acc+=elapsed;
  dec = decrypt(result, key);
  printf("  EQ: %d =? %d ==> %d\n", a, a, dec);
  printf("  timing: %.5f\n\n", elapsed);
  
  printf("Comparisons \n");
  clock_gettime(CLOCK_REALTIME, &begin);
  GT(result, ca, cb, key, ks_key);
  clock_gettime(CLOCK_REALTIME, &end);
  seconds = end.tv_sec - begin.tv_sec;
  nanoseconds = end.tv_nsec - begin.tv_nsec;
  elapsed = seconds + nanoseconds*1e-9;
  dec = decrypt(result, key);
  printf("  GT: %d >? %d ==> %d\n", a, b, dec);
  printf("  timing: %.5f\n", elapsed);

  clock_gettime(CLOCK_REALTIME, &begin);
  GTE(result, ca, cb, key, ks_key);
  clock_gettime(CLOCK_REALTIME, &end);
  seconds = end.tv_sec - begin.tv_sec;
  nanoseconds = end.tv_nsec - begin.tv_nsec;
  elapsed = seconds + nanoseconds*1e-9;
  dec = decrypt(result, key);
  printf("  GTE: %d >=? %d ==> %d\n", a, b, dec);
  printf("  timing: %.5f\n", elapsed);

  clock_gettime(CLOCK_REALTIME, &begin);
  LT(result, ca, cb, key, ks_key);
  clock_gettime(CLOCK_REALTIME, &end);
  seconds = end.tv_sec - begin.tv_sec;
  nanoseconds = end.tv_nsec - begin.tv_nsec;
  elapsed = seconds + nanoseconds*1e-9;
  dec = decrypt(result, key);
  printf("  LT: %d <? %d ==> %d\n", a, b, dec);
  printf("  timing: %.5f\n", elapsed);

  clock_gettime(CLOCK_REALTIME, &begin);
  LT(result, cb, ca, key, ks_key);
  clock_gettime(CLOCK_REALTIME, &end);
  seconds = end.tv_sec - begin.tv_sec;
  nanoseconds = end.tv_nsec - begin.tv_nsec;
  elapsed = seconds + nanoseconds*1e-9;
  dec = decrypt(result, key);
  printf("  LT: %d <? %d ==> %d\n", b, a, dec);
  printf("  timing: %.5f\n", elapsed);

  
  clock_gettime(CLOCK_REALTIME, &begin);
  LTEi(result, ca, a, key, ks_key);
  clock_gettime(CLOCK_REALTIME, &end);
  seconds = end.tv_sec - begin.tv_sec;
  nanoseconds = end.tv_nsec - begin.tv_nsec;
  elapsed = seconds + nanoseconds*1e-9;
  dec = decrypt(result, key);
  printf("  LTEi: %d <=? %d ==> %d\n", a, a, dec);
  printf("  timing: %.5f\n\n", elapsed);
  
  
  printf("Conditional Affectation \n");
  clock_gettime(CLOCK_REALTIME, &begin);
  CDUP(result, one[1], cb, key, ks_key);
  clock_gettime(CLOCK_REALTIME, &end);
  seconds = end.tv_sec - begin.tv_sec;
  nanoseconds = end.tv_nsec - begin.tv_nsec;
  elapsed = seconds + nanoseconds*1e-9;
  dec = decrypt(result, key);
  printf("  CDUP(1, %d)  = %d\n", b, dec);
  printf("  timing: %.5f\n", elapsed);

  clock_gettime(CLOCK_REALTIME, &begin);
  CDUP(result, zero[1], cb, key, ks_key);
  clock_gettime(CLOCK_REALTIME, &end);
  seconds = end.tv_sec - begin.tv_sec;
  nanoseconds = end.tv_nsec - begin.tv_nsec;
  elapsed = seconds + nanoseconds*1e-9;
  dec = decrypt(result, key);
  printf("  CDUP(0, %d)  = %d\n", b, dec);
  printf("  timing: %.5f\n", elapsed);

  clock_gettime(CLOCK_REALTIME, &begin);
  CDUPi(result, one[1], b, key, ks_key);
  clock_gettime(CLOCK_REALTIME, &end);
  seconds = end.tv_sec - begin.tv_sec;
  nanoseconds = end.tv_nsec - begin.tv_nsec;
  elapsed = seconds + nanoseconds*1e-9;
  dec = decrypt(result, key);
  printf("  CDUPi(%d, %d)  = %d\n", 1, b, dec);
  printf("  timing: %.5f\n", elapsed);

  
  clock_gettime(CLOCK_REALTIME, &begin);
  NCDUP(result, ca[1], cb, key, ks_key);
  clock_gettime(CLOCK_REALTIME, &end);
  seconds = end.tv_sec - begin.tv_sec;
  nanoseconds = end.tv_nsec - begin.tv_nsec;
  elapsed = seconds + nanoseconds*1e-9;
  dec = decrypt(result, key);
  printf("  NCDUP(%d, %d)  = %d\n", a, b, dec);
  printf("  timing: %.5f\n", elapsed);

  clock_gettime(CLOCK_REALTIME, &begin);
  NCDUP(result, zero[1], cb, key, ks_key);
  clock_gettime(CLOCK_REALTIME, &end);
  seconds = end.tv_sec - begin.tv_sec;
  nanoseconds = end.tv_nsec - begin.tv_nsec;
  elapsed = seconds + nanoseconds*1e-9;
  dec = decrypt(result, key);
  printf("  NCDUP(%d, %d)  = %d\n", 0, b, dec);
  printf("  timing: %.5f\n", elapsed);

  clock_gettime(CLOCK_REALTIME, &begin);
  NCDUP(result, one[1], cb, key, ks_key);
  clock_gettime(CLOCK_REALTIME, &end);
  seconds = end.tv_sec - begin.tv_sec;
  nanoseconds = end.tv_nsec - begin.tv_nsec;
  elapsed = seconds + nanoseconds*1e-9;
  dec = decrypt(result, key);
  printf("  NCDUP(%d, %d)  = %d\n", 1, b, dec);
  printf("  timing: %.5f\n\n", elapsed);

  printf("CSEL\n");
  clock_gettime(CLOCK_REALTIME, &begin);
  CSEL(result, one[1], ca, cb, key, ks_key);
  clock_gettime(CLOCK_REALTIME, &end);
  seconds = end.tv_sec - begin.tv_sec;
  nanoseconds = end.tv_nsec - begin.tv_nsec;
  elapsed = seconds + nanoseconds*1e-9;
  dec = decrypt(result, key);
  printf("  CSEL(1, %d, %d)  = %d\n", a, b, dec);
  printf("  timing: %.5f\n\n", elapsed);

  clock_gettime(CLOCK_REALTIME, &begin);
  CSEL(result, zero[1], ca, cb, key, ks_key);
  clock_gettime(CLOCK_REALTIME, &end);
  seconds = end.tv_sec - begin.tv_sec;
  nanoseconds = end.tv_nsec - begin.tv_nsec;
  elapsed = seconds + nanoseconds*1e-9;
  dec = decrypt(result, key);
  printf("  CSEL(0, %d, %d)  = %d\n", a, b, dec);
  printf("  timing: %.5f\n\n", elapsed);
  
  printf("Absolute value \n");
  clock_gettime(CLOCK_REALTIME, &begin);
  ABS(result, ca, key, ks_key);
  clock_gettime(CLOCK_REALTIME, &end);
  seconds = end.tv_sec - begin.tv_sec;
  nanoseconds = end.tv_nsec - begin.tv_nsec;
  elapsed = seconds + nanoseconds*1e-9;
  int dec_sign = decrypt_sign(result, key);
  printf("  ABS(%d) = %d\n", a, dec_sign);
  printf("  timing: %.5f\n", elapsed);

  clock_gettime(CLOCK_REALTIME, &begin);
  ABS(result, cb, key, ks_key);
  clock_gettime(CLOCK_REALTIME, &end);
  seconds = end.tv_sec - begin.tv_sec;
  nanoseconds = end.tv_nsec - begin.tv_nsec;
  elapsed = seconds + nanoseconds*1e-9;
  dec_sign = decrypt_sign(result, key);
  printf("  ABS(%d) = %d\n", b, dec_sign);
  printf("  timing: %.5f\n\n", elapsed);

  printf("Negation\n");
  clock_gettime(CLOCK_REALTIME, &begin);
  NEG(result, cb, key, ks_key);
  clock_gettime(CLOCK_REALTIME, &end);
  seconds = end.tv_sec - begin.tv_sec;
  nanoseconds = end.tv_nsec - begin.tv_nsec;
  elapsed = seconds + nanoseconds*1e-9;
  dec_sign = decrypt_sign(result, key);
  printf("  NEG(%d) = %d\n", b, dec_sign);
  printf("  timing: %.5f\n", elapsed);

   clock_gettime(CLOCK_REALTIME, &begin);
  NEG(result, ca, key, ks_key);
  clock_gettime(CLOCK_REALTIME, &end);
  seconds = end.tv_sec - begin.tv_sec;
  nanoseconds = end.tv_nsec - begin.tv_nsec;
  elapsed = seconds + nanoseconds*1e-9;
  dec_sign = decrypt_sign(result, key);
  printf("  NEG(%d) = %d\n", a, dec_sign);
  printf("  timing: %.5f\n\n", elapsed);

  word8 tab_msb[argc-1];
  word8 tab_lsb[argc-1];
  for(int i=0; i<argc-1; i++){
    tab_msb[i]= tab_clear[i]/16;
    tab_lsb[i]= tab_clear[i]%16;
  }
  
  vector<LweSample*> v;
  vector<LweSample*> result2;
  for(int i=0; i<argc-1; i++){
    v.push_back(new_LweSample(key->lwe_key->params));
    lweSymEncrypt(v[2*i], modSwitchToTorus32(tab_msb[i], 32), alpha, key->lwe_key);
    v.push_back(new_LweSample(key->lwe_key->params));
    lweSymEncrypt(v[2*i+1], modSwitchToTorus32(tab_lsb[i], 32), alpha, key->lwe_key);

    result2.push_back(new_LweSample(key->lwe_key->params));
    result2.push_back(new_LweSample(key->lwe_key->params));
  }
  vector<vector<LweSample*>> av;
  for(int i=0; i<argc-1; i++){
    vector<LweSample*> tmp;   
    tmp.push_back(new_LweSample(key->lwe_key->params));
    lweSymEncrypt(tmp[0], modSwitchToTorus32(tab_msb[i], 32), alpha, key->lwe_key);
    tmp.push_back(new_LweSample(key->lwe_key->params));
    lweSymEncrypt(tmp[1], modSwitchToTorus32(tab_lsb[i], 32), alpha, key->lwe_key);
    av.push_back(tmp);

  }
  
   vector<LweSample*> tmp;   
   tmp.push_back(new_LweSample(key->lwe_key->params));
   tmp.push_back(new_LweSample(key->lwe_key->params));
   printf("/****************************************************************************/\n");
   printf("Now we execute several algorithm on Table [ ");
   for(int i=0; i<argc-1; i++)
     printf("%d ",tab_clear[i]);
   printf("]\n");
   printf("Bubble sort\n");
   clock_gettime(CLOCK_REALTIME, &begin);
   bubble_sort(av, argc-1, key, ks_key);
   clock_gettime(CLOCK_REALTIME, &end);
   seconds = end.tv_sec - begin.tv_sec;
   nanoseconds = end.tv_nsec - begin.tv_nsec;
   elapsed = seconds + nanoseconds*1e-9;
   printf("Sorted Array: ");
   for(int i=0; i<argc-1; i++){
     lweCopy(tmp[0], av[i][0], key->lwe_key->params);
     lweCopy(tmp[1], av[i][1], key->lwe_key->params);
     dec= decrypt(tmp, key);
     printf("%d ", dec);
   }
   printf("\ntiming : %.5f\n\n", elapsed);
  
 
   printf("Maximum of Array \n");
   clock_gettime(CLOCK_REALTIME, &begin);
   maximum(result, v, argc-1, key, ks_key);
   clock_gettime(CLOCK_REALTIME, &end);
   seconds = end.tv_sec - begin.tv_sec;
   nanoseconds = end.tv_nsec - begin.tv_nsec;
   elapsed = seconds + nanoseconds*1e-9;
   dec= decrypt(result, key);
   printf("Maximum of Array: %d\n ", dec);
   printf("timing : %.5f\n\n", elapsed);
  
  
   printf("Average of Array\n");
   clock_gettime(CLOCK_REALTIME, &begin);
   average(result2, v, argc-1, key, ks_key);
   clock_gettime(CLOCK_REALTIME, &end);
   seconds = end.tv_sec - begin.tv_sec;
   nanoseconds = end.tv_nsec - begin.tv_nsec;
   elapsed = seconds + nanoseconds*1e-9;
   lweCopy(tmp[0], result2[2], key->lwe_key->params);
   lweCopy(tmp[1], result2[3], key->lwe_key->params);
   float dec_f= decrypt_dec(tmp, key);
   dec= decrypt(result2, key);
   float q=0;
   for(int i=0; i<argc-1; i++)
     q=(int)(q + tab_clear[i])%256;
   q= q/(argc-1);
   printf("Average: %.5f (should be %f)\n", dec+ dec_f, q);
   printf("timing : %.5f\n\n",  elapsed);

  
   printf("Squares Sum\n");
   clock_gettime(CLOCK_REALTIME, &begin);
   squaresum(result, v, argc-1, key, ks_key);
   clock_gettime(CLOCK_REALTIME, &end);
   seconds = end.tv_sec - begin.tv_sec;
   nanoseconds = end.tv_nsec - begin.tv_nsec;
   elapsed = seconds + nanoseconds*1e-9;
   dec= decrypt(result, key);
   int sum=0;
   for(int i=0; i<argc-1; i++)
     sum+=tab_clear[i]*tab_clear[i];
   printf("Squares Sum: %d (should be %d)\n ", dec, sum%256);
   printf("timing : %.5f\n\n", elapsed);

   
   printf("Array Assignment: we assign an encryption of 0 in position 1.\n");
   lweSymEncrypt(one[0], modSwitchToTorus32(0, 32), alpha, key->lwe_key);
   lweSymEncrypt(one[1], modSwitchToTorus32(1, 32), alpha, key->lwe_key);
   clock_gettime(CLOCK_REALTIME, &begin);
   array_assign(v, zero, one, argc-1, key, ks_key);
   clock_gettime(CLOCK_REALTIME, &end);
   seconds = end.tv_sec - begin.tv_sec;
   nanoseconds = end.tv_nsec - begin.tv_nsec;
   elapsed = seconds + nanoseconds*1e-9;
   printf("New Array: ");
   for(int i=0; i<argc-1; i++){
     lweCopy(tmp[0], v[2*i], key->lwe_key->params);
     lweCopy(tmp[1], v[2*i+1], key->lwe_key->params);
     dec= decrypt(tmp, key);
     printf("%d ", dec);
   }
   printf("\ntiming : %.5f\n\n", elapsed);
  printf("/****************************************************************************/\n");
  printf("Now, we test some 16-bit fixed-point arithmetic operations.\n");
  test_16(key, ks_key, alpha);
  
  delete_gate_bootstrapping_secret_keyset(key);
  delete_gate_bootstrapping_parameters(params);
  delete_BaseBKeySwitchKey(ks_key);
  printf("\ndone\n");
  
  return 0;
}



