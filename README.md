# Artifact for "Designing an 8-bit General-Purpose (T)FHE Processor Abstraction"

This is the source code of the 8-bit TFHE processor abstraction proposed in the paper ``Designing an 8-bit General-Purpose (T)FHE Processor Abstraction'' which has been accepted to CHES 2025 (available as a preprint on the [IACR ePrint](https://eprint.iacr.org/2024/1201)). 
It relies on version 1.1 of the TFHElib library (which runs over C++). Our artifact implements each instruction given in the paper (the complete list is in Appendix A of the paper) as well as the algorithms designed as a benchmark for the new approach (see Table 6 in Section 8).   
All multivariate instructions are implemented in the instr.cpp file. The corresponding header instr.h defines each function of instr.cpp and give the corresponding section in the article. 
In the same fashion, we have respectively created the instri.cpp (resp. algos.cpp and instr_16.cpp) files to implement the univariate instructions (resp. the algorithms and 16-bit fixed point arithmetic operations) and their corresponding headers instri.h (resp. algos.h and instr_16.h) that link the functions to the correct sections of the paper.
The main is composed of an exhaustive set of tests that allows to execute each instruction and algorithm on inputs that are given by the user.

## Download the Artifact

1/ git clone https://github.com/daphnetrm/tfhe_instruction_set.git    
2/ cd tfhe_instruction_set    


## Install TFHElib

To run the code, you first have to install the TFHElibrary (https://tfhe.github.io/tfhe/) and apply the patch provided in the file patch_fft.patch. The git clone command should automatically install version 1.1 of TFHElib, which we used to implement our work.

3/ git clone https://github.com/tfhe/tfhe.git   
4/ cd tfhe      
5/ git apply ../patch_fft.patch   
6/ make    
7/ cd ..       


## Run the code

Once TFHElib version 1.1 and the provided patch are installed, and you have downloaded the source-code, go in the newly created root directory (it should contain a "sources" folder), and:

Update the path to the TFHElib directory in the provided sources/CMakeList.txt:   
"set(TFHE_PREFIX ../tfhe)" if you just installed the library in the root directory; otherwise, update the path accordingly to our installation.

     
8/  cmake -S . -B ./build       
9/  cd build   
10/ make    
11/ ../bin/tches <n1> <n2> <n3> <n4> <n5>   
WARNING: n2 should not be null because it is used as a divisor, and a floating point exception will occur.

The last command will run an exhaustive test of all our instructions with timing measurements on inputs n1 and n2.     
Then, it will run an exhaustive test of all our algorithm implementations on the array composed of n1, n2, n3, n4, and n5. (The n_i must be byte values).
Finally, the program will execute some 16-bit fixed-point arithmetic operations, including the execution of a neuron with sigmoid.
Note that you can enter as many bytes as you want as long as you give at least two of them.

## Instructions on how to interpret the outputs

The execution timings, as well as the instruction/algorithm being executed and the corresponding results, are printed on the terminal. The program will firstly output the homomorphic execution of our instruction set (both multivariate and univariate instructions) corresponding to Table 4 (Section 7) and Appendix A in the paper. 
Then, the program will output the results of the execution of the algorithms presented in Section 8 of the article. Finally, some 16-bit fixed-point arithmetic instructions will be performed, including the homomorphic evaluation of a neuron with activation function sigmoid.
The user will easily recognize the instructions being tested as they are denoted with the notations given in the paper. For instance, the addition of two 8-bit payload ciphertexts encrypting 45 and 103 will output:

  ADD(45 + 103) = 148    
  timing : 0.49377s

This allows the user to verify if the homomorphic results are correct and to check the timings. 
For comparison, the execution timings obtained on our machine with the same code are given in Appendix A and Section 8 of the article. Finally, we give in the "ref_output.txt" file what the execution of the program with inputs 42, 5, 12, 203, and 127 produces on our machine.
