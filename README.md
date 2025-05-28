![Python](https://img.shields.io/badge/python-3.9-green)
![License](https://img.shields.io/github/license/okhobian/decentralized-situ)
![Last Commit](https://img.shields.io/github/last-commit/okhobian/decentralized-situ)


# Verifiable Personalized Mutual-Learning based on Blockchain and zk-SNARK


### Instructions on Running the Experiments

---

### Key Prerequisites

- [Truffle Ganache](https://archive.trufflesuite.com/ganache/) v7.9.2 (@ganache/cli: 0.10.2, @ganache/core: 0.10.2)
- [Remix IDE](http://remix.ethereum.org)
- [Zokrates](https://zokrates.github.io/gettingstarted.html) v0.8.8
- Python 3.9
- Keras-TensorFlow v2.13.1
- scikit-learn v1.3.1

- NOTE: other blockchain testnets and compilation methods should also work, configurations may vary.
---

### Mutual-Learning

1. Navigate to `learning-experiment`. Key scripts include:
   - `train_models.py`: original model training
   - `distil_models.py`: for model distillation
   - `exp_exe.py`: mutual-learning experiments

2. To run:
   ```bash
   python <script.py>  # Hyperparameters are defined at the top of each script.
   ```
---

### Local Verification

1. Navigate to `local-verify-experiment`.
2. Use [RemixIDE](http://remix.ethereum.org) (other compilation methods may work, configurations may vary).
3. Upload `ModelVerification.sol` to RemixIDE under `/contracts`.
4. In the Solidity Compiler:
   - Select version `0.8.12`.
   - Check "Use configuration file".
5. Compile the contract.
6. Copy the `ABI` to `abi.json` in this directory.
7. Copy the `Bytecode` to `contract_bytecode` in `verify.py` (remove the `0x` prefix).
8. Start local Truffle Ganache at `localhost:8545`.
9. Run the experiment:
   ```bash
   python verify.py  # Cost estimates will be saved to `results.csv`.
   ```   
10. Use `exp_out.ipynb` to visualize the results.

---

### Global Multi-Signature zk Verification

1. Navigate to `zokrate-demo/test/multi-signature`.
2. Modify `N` in both `verify_signature.zok` and `zokrate-exp.py` for `N` verifiers.
3. Run:
   ```bash
   python zokrate-exp.py
   ```
   Note: This compiles the circuit, generates the verifying contract, and outputs cost estimates. The script also uses local Zokrates to verify the generated proof, with output displayed in the CLI.

4. To verify on-chain, deploy the generated contract `verifier.sol` to local Truffle Ganache:
   - Upload `verifier.sol` to Remix IDE under `/contracts`.
   - In the Solidity Compiler:
     - Select version `0.8.20`.
     - Use EVM version `Shanghai`.
     - Enable optimization with 1000 runs.
   - Start local Truffle Ganache at `localhost:8545`:
     ```bash
     ganache --chain.allowUnlimitedContractSize true --chain.allowUnlimitedInitCodeSize true --gasLimit 0xFFFFFFFFFFF
     ```
   - In Remix IDE:
     - Set the environment to local Truffle Ganache.
     - Select a custom gas limit of `12000000000` for deployment.
   - Deploy `verifier.sol`.
   - Prepare verifying parameters:
     ```bash
     python gen_remix_params.py  # Output: `tester.json`.
     ```
   - In Remix IDE:
     - Navigate to Deployed Contracts.
     - Expand `verifyTx`.
     - Copy corresponding values from `tester.json` to `proof` and `input`.
     - Click `call`.
   - Once the transaction is completed, check the verifying result in the `decoded output: bool`.

5. [Optional] To view gas estimation:
   - Remove the `view` modifier from the Zokrates auto-generated function `verifyTx` to obtain gas consumption.
   - After the transaction is completed, check gas consumption in the block details (in Remix IDE output).

6. To clean up:
   ```bash
   ./remove_zokrates_files.sh
   ```

---

### Miscellaneous

- Follow `ezkl-experiment/ezkl_demo.ipynb` for EZKL-based exmaple.
- Use `local-verify-experiment/selection_relation.py` to determine the number of worker requirements. Visualize with `local-verify-experiment/exp_out.ipynb`.