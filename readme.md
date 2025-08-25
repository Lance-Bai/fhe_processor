# Artifact for "Tetris: A Versatile TFHE Look-Up-Table Framework and Its Application to FHE Instruction Set"

## Download the Artifact

This artifact is avaliable on [anonymous.4open.science](https://anonymous.4open.science/r/artifact_of_fhe_processor/) and can be download with:

```bash
curl -L -o fhe_processor.zip \
  "https://anonymous.4open.science/api/repo/artifact_of_fhe_processor/zip"
```

or

```bash
wget -O fhe_processor.zip \
  "https://anonymous.4open.science/api/repo/artifact_of_fhe_processor/zip"
```

Then unzip it and enter the workspace:

```bash
unzip fhe_processor.zip 
```

## Evaluate the [Benchmark](./benches/)

### [LUT time evaluation](./benches/lut_bench.rs)

This bench is correspond to the **Table 2: LUT time results** in the article. It test the execution time of n-to-n LUT with the same calculation process used in the FHE processor. It provide 2 parameter set which is **SetI** and **SetI_large**, and support bits precision from **4 to 32**, threads from **1 to 8**. For large precision may require huge amount of time and memory, by default we set precision up to 24 bits. To test high precision, modify should be done to [here](./benches/lut_bench.rs#L293-L295).

```RUST
    let ctx = setup_ctx(*SetI);
    let n_vals = [4, 8, 12, 16, 20, 24,];
    let thread_vals = [1, 2, 4, 8];
```

After set the config or just use the default config, the bench can be run with:

```bash
cargo bench --bench lut_bench
```

Then the time shown in the concole is the total time for each precision-thread group. The more detailed information for each iters and the seprete time for circuit boostrapping and table look up is stored in [log](./target/bench_logs), which is also the data shown in **Table 3**.

### [Processor operations evaluation](./benches/all_op_bench.rs)

This bench correspond the **Table 5** in the article, it test all the operations with 8-bit data len with all modes of **cipher-cipher**, **cipheriplain** and **plain-cipher**. This branch can be run with default the multithread option. Will the data used in article is the performance in single thread for fairness, which can be evaluated with the below line.

```bash
cargo bench --bench all_op_bench
or
RAYON_NUM_THREADS=1 cargo bench --bench all_op_bench
```

### [Typical programs evaluation](./benches/program_bench.rs)

This bench correspond to **Table 6**. It test 4 typical programs to evaluate the performance of the FHE processor. For each program, it will load 5 8-bit unsigned integer as the input. The programs are **Maximum**, find the largest value. **Bubble Sort**, do bubble sort to the 5 input, from small to large. **Square Sum**, calculate the square of each input then add then together. **Average**, calculate the average value of the 5 input. All of these programs are executed with the below, still, the data represent in the article is in single thread.

```bash
cargo bench --bench program_bench
or
RAYON_NUM_THREADS=1 cargo bench --bench program_bench
```

### [Large precision compare Opmization](./benches/large_op_bench.rs)

This bench correspond to **Table 7**. It test the performance of opmized compare instruction and trival compare instruction. As all the compare instruction has same implemention, we only test **GTE** here. Besides, **GTE_ORI** is the trival implemention, and it is slow when has 32 bits inputs, so we not open it by default. If necessary remove the commont [here](./benches/large_op_bench.rs#L34-L36) to enable the test. The bench is run with:

```bash
cargo bench --bench large_op_bench
or
RAYON_NUM_THREADS=1 cargo bench --bench large_op_bench
```
