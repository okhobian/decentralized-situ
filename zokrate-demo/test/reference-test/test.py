import subprocess
import time
import json
import random

# ZoKrates file to test
ZOKRATES_FILE = "root.zok"  # The main ZoKrates circuit

# Parameters for random data generation
FEATURES = 9  # Number of features (fe)
ACTIVATIONS = 6  # Number of activations (ac)
BATCH_SIZE = 10  # Number of training examples (bs)
PRECISION = 1000  # Precision for field values

# Random data generator for testing
def generate_random_data():
    return {
        "w": [[random.randint(0, PRECISION) for _ in range(FEATURES)] for _ in range(ACTIVATIONS)],
        "w_sign": [[random.randint(0, 1) for _ in range(FEATURES)] for _ in range(ACTIVATIONS)],
        "b": [random.randint(0, PRECISION) for _ in range(ACTIVATIONS)],
        "b_sign": [random.randint(0, 1) for _ in range(ACTIVATIONS)],
        "x_train": [[random.randint(0, PRECISION) for _ in range(FEATURES)] for _ in range(BATCH_SIZE)],
        "x_train_sign": [[random.randint(0, 1) for _ in range(FEATURES)] for _ in range(BATCH_SIZE)],
        "y_train": [random.randint(1, ACTIVATIONS) for _ in range(BATCH_SIZE)],
        "learning_rate": random.randint(1, PRECISION),
        "pr": PRECISION,
        "w_new": [[random.randint(0, PRECISION) for _ in range(FEATURES)] for _ in range(ACTIVATIONS)],
        "b_new": [random.randint(0, PRECISION) for _ in range(ACTIVATIONS)],
        "R": [random.randint(0, PRECISION) for _ in range(2)],
        "S": random.randint(0, PRECISION),
        "A": [random.randint(0, PRECISION) for _ in range(2)],
        "M0": [random.randint(0, PRECISION) for _ in range(8)],
        "M1": [random.randint(0, PRECISION) for _ in range(8)],
        "commitment": [random.randint(0, PRECISION) for _ in range(8)],
    }

# Generate random inputs
zokrates_input_data = generate_random_data()

# Helper function to execute ZoKrates commands
def run_command(command, input_data=None):
    start = time.time()
    result = subprocess.run(
        command, input=input_data, text=True, capture_output=True
    )
    end = time.time()
    return result, end - start

# Step 0: Compile the circuit
print("Compiling the circuit...")
compile_result, compile_time = run_command(["zokrates", "compile", "-i", ZOKRATES_FILE])
print(f"Compile Time: {compile_time:.2f}s")
print(compile_result.stdout)
if compile_result.stderr:
    print("Errors:", compile_result.stderr)

# Step 1: Setup
print("\nSetting up...")
setup_result, setup_time = run_command(["zokrates", "setup"])
print(f"Setup Time: {setup_time:.2f}s")
print(setup_result.stdout)
if setup_result.stderr:
    print("Errors:", setup_result.stderr)

# Step 2: Compute witness
print("\nComputing the witness...")
zokrates_input_json = json.dumps(zokrates_input_data)
compute_result, compute_time = run_command(
    ["zokrates", "compute-witness", "--abi", "--stdin"], input_data=zokrates_input_json
)
print(f"Compute Witness Time: {compute_time:.2f}s")
print(compute_result.stdout)
if compute_result.stderr:
    print("Errors:", compute_result.stderr)

# Step 3: Generate proof
print("\nGenerating proof...")
proof_result, proof_time = run_command(["zokrates", "generate-proof"])
print(f"Generate Proof Time: {proof_time:.2f}s")
print(proof_result.stdout)
if proof_result.stderr:
    print("Errors:", proof_result.stderr)

# Step 4: Verify proof
print("\nVerifying proof...")
verify_result, verify_time = run_command(["zokrates", "verify"])
print(f"Verify Proof Time: {verify_time:.2f}s")
print(verify_result.stdout)
if verify_result.stderr:
    print("Errors:", verify_result.stderr)

# Summary
print("\n==== Summary ====")
print(f"Compile Time: {compile_time:.2f}s")
print(f"Setup Time: {setup_time:.2f}s")
print(f"Compute Witness Time: {compute_time:.2f}s")
print(f"Generate Proof Time: {proof_time:.2f}s")
print(f"Verify Proof Time: {verify_time:.2f}s")
