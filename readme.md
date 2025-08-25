# Artifact for *Tetris: A Versatile TFHE Look-Up-Table Framework and Its Application to FHE Instruction Set*

## Downloading the Artifact

The artifact is available on [anonymous.4open.science](https://anonymous.4open.science/r/artifact_of_fhe_processor/) and can be downloaded using:

```bash
curl -L -o fhe_processor.zip \
  "https://anonymous.4open.science/api/repo/artifact_of_fhe_processor/zip"
```

or

```bash
wget -O fhe_processor.zip \
  "https://anonymous.4open.science/api/repo/artifact_of_fhe_processor/zip"
```

Unzip and enter the workspace:

```bash
unzip fhe_processor.zip
cd artifact_of_fhe_processor
```

---

## Environment & Dependencies

- **Rust**: Version 1.79 or later (tested with Rust 1.81 stable)
- **Cargo**: Bundled with Rust toolchain
- **Operating System**:
  - Linux (Ubuntu 24.10 LTS, tested)
- **Memory**: ≥ 24 GB recommended (tested)
- **Other tools**: `wget` or `curl` for artifact download

---

## Quick Start

To quickly try out the FHE processor, you can run the example test defined in [lib.rs](./src/lib.rs).  
Execute the following command:

```bash
cargo test --release --package fhe_processor -- manager_tests --show-output
```

This will run the processor test suite and display the results directly in the console.

---

## Benchmark Evaluation

### [LUT Time Evaluation](./benches/lut_bench.rs)

This benchmark corresponds to **Table 2: LUT time results** in the paper.  
It measures the execution time of *n-to-n LUTs* using the same computation pipeline as the FHE processor.  

- Provides two parameter sets: **SetI** and **SetI_large**  
- Supports precision from **4 to 32 bits**  
- Supports **1–8 threads**  

> **Note:** High-precision tests may require significant time and memory. By default, the maximum precision is set to 24 bits.  
To test higher precision, modify the configuration at [these 3 lines](./benches/lut_bench.rs#L292-L294).

```rust
let ctx = setup_ctx(*SetI);
let n_vals = [4, 8, 12, 16, 20, 24];
let thread_vals = [1, 2, 4, 8];
```

Run with:

```bash
cargo bench --bench lut_bench
```

- The console output reports the total execution time for each precision–thread group.  
- Detailed iteration results and separated timings for *circuit bootstrapping* and *table lookup* are stored in [log](./target/bench_logs), corresponding to **Table 3**.

---

### [Processor Operations Evaluation](./benches/all_op_bench.rs)

This benchmark corresponds to **Table 5** in the paper.  
It evaluates all operations with 8-bit inputs under three modes:  

- **cipher–cipher**  
- **cipher–plain**  
- **plain–cipher**

By default, benchmarks run with multithreading enabled.  
For fairness (as in the paper), single-thread performance can be measured with:

```bash
RAYON_NUM_THREADS=1 cargo bench --bench all_op_bench
```

---

### [Typical Programs Evaluation](./benches/program_bench.rs)

This benchmark corresponds to **Table 6** in the paper.  
It evaluates four representative programs on five unsigned 8-bit inputs:  

- **Maximum**: Find the largest value  
- **Bubble Sort**: Sort the inputs in ascending order  
- **Square Sum**: Compute the sum of squared inputs  
- **Average**: Compute the average value  

Run with:

```bash
RAYON_NUM_THREADS=1 cargo bench --bench program_bench
```

Again, single-thread results are used in the paper for comparison.

---

### [Large-Precision Comparison Optimization](./benches/large_op_bench.rs)

This benchmark corresponds to **Table 7** in the paper.  
It compares optimized and trivial implementations of comparison instructions.  

- Only **GTE** is tested, since all comparisons share the same implementation.  
- **GTE_ORI** is the trivial version; it is slow for 32-bit inputs and disabled by default.  
  To enable, uncomment [this section](./benches/large_op_bench.rs#L34-L36).

Run with:

```bash
RAYON_NUM_THREADS=1 cargo bench --bench large_op_bench
```
