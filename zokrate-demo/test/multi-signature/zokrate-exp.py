import os
import hashlib
import json
import subprocess
import time
import csv
from zokrates_pycrypto.eddsa import PrivateKey, PublicKey
from zokrates_pycrypto.field import FQ

# add ZoKrates to PATH if it's not already there
zokrates_path = os.path.expanduser("~/.zokrates/bin")
if zokrates_path not in os.environ["PATH"]:
    os.environ["PATH"] += os.pathsep + zokrates_path

###########################################################################################################
ZOKRATES_FILE = "verify_signature.zok"  # zoKrates source file
N = 5                                   # number of signatures (should match N in the ZoKrates circuit)
T = 3                                   # threshold of valid signatures

def generate_signature_data(message):
    # make a random private key
    sk = PrivateKey.from_rand()
    pk = PublicKey.from_private(sk)

    # hash the message
    msg_hash = hashlib.sha512(message.encode("utf-8")).digest()

    # sign the message hash, which returns (R, S) as a tuple
    R, S = sk.sign(msg_hash)

    # prepare the parts for ZoKrates
    R = [str(R.x), str(R.y)]  # signature point coordinates (x, y)
    S = str(S)                # scalar part of the signature as a string
    A = [str(pk.p.x.n), str(pk.p.y.n)]  # public key point coordinates

    # split the hashed message into two 8-element arrays of 32-bit integers
    M0, M1 = split_hash_to_u32_arrays(msg_hash)

    return {"R": R, "S": S, "A": A, "M0": M0, "M1": M1}

def split_hash_to_u32_arrays(hashed_message):
    # breaks down a 64-byte message hash into two arrays of eight 32-bit integers
    M0 = [str(int.from_bytes(hashed_message[i:i+4], 'big')) for i in range(0, 32, 4)]
    M1 = [str(int.from_bytes(hashed_message[i:i+4], 'big')) for i in range(32, 64, 4)]
    return M0, M1

def compute_final_hash(public_keys):
    MODULO = 2**256  # Ensure the sum fits within 256 bits
    total_sum = 0

    # for key in public_keys:
    #     total_sum = (total_sum + int(key[0]) + int(key[1])) % MODULO

    # # Convert the reduced total_sum directly to bytes
    # total_sum_bytes = total_sum.to_bytes(32, "big")

    # # Compute the Keccak hash
    # hash_result = hashlib.sha256(total_sum_bytes).digest()

    # Convert hash_result to 8 integers for ZoKrates input (field[8] equivalent)
    # return [int.from_bytes(hash_result[i:i+4], "big") for i in range(0, 32, 4)]
    return "0" # for performance testing. dont effect proof of concept

def get_file_size(file_path):
    if os.path.exists(file_path):
        size = os.path.getsize(file_path)
        if size >= 1_000_000_000:  # convert to GB if >= 1 GB
            return f"{size / 1_000_000_000:.2f} GB"
        elif size >= 1_000_000:    # convert to MB if >= 1 MB
            return f"{size / 1_000_000:.2f} MB"
        elif size >= 1_000:        # convert to KB if >= 1 KB
            return f"{size / 1_000:.2f} KB"
        else:                      # use bytes for smaller files
            return f"{size} Bytes"
    return "File not found"

def create_tester_json(proof_file, tester_file):
    try:
        with open(proof_file, "r") as f:
            proof_data = json.load(f)
        
        proof = proof_data["proof"]
        inputs = proof_data["inputs"]

        transformed_proof = [
            proof["a"],
            proof["b"],
            proof["c"]
        ]

        tester_data = {
            "proof": transformed_proof,
            "inputs": inputs
        }

        with open(tester_file, "w") as f:
            json.dump(tester_data, f, indent=4)
        
        print(f"Tester file created successfully: {tester_file}")
    except Exception as e:
        print(f"Error creating tester.json: {e}")

# create messages and generate a signature for each
messages = [f"This is message {i}" for i in range(N)]
signature_data = [generate_signature_data(msg) for msg in messages]
final_hash = compute_final_hash(None)

# circuit inputs
zokrates_input = {
    "R": [sig["R"] for sig in signature_data],
    "S": [sig["S"] for sig in signature_data],
    "A": [sig["A"] for sig in signature_data],
    "M0": [sig["M0"] for sig in signature_data],
    "M1": [sig["M1"] for sig in signature_data],
    "final_hash": final_hash,
    "T": str(T)
}

# convert to a JSON array format
zokrates_input_json = json.dumps([
    zokrates_input["R"], zokrates_input["S"], zokrates_input["A"], zokrates_input["M0"], zokrates_input["M1"], zokrates_input["final_hash"], zokrates_input["T"]
])

# to store command execution times and file sizes
command_times = []
file_sizes = {}

# Step 0: Compile the ZoKrates circuit
print("\n[Stage: Compile] Compiling the ZoKrates circuit...")
start = time.time()
result_compile = subprocess.run(
    ["zokrates", "compile", "-i", ZOKRATES_FILE],
    text=True,
    capture_output=True
)
end = time.time()
command_times.append(("Compile", end - start))
file_sizes["out"] = get_file_size("out")
print("==== ZoKrates Compile ====")
print("Output:", result_compile.stdout)
if result_compile.stderr:
    print("Error:", result_compile.stderr)

# Step 1: Setup for the ZoKrates program
print("\n[Stage: Setup] Performing setup to generate proving and verification keys...")
start = time.time()
result_setup = subprocess.run(
    ["zokrates", "setup"],
    text=True,
    capture_output=True
)
end = time.time()
command_times.append(("Setup", end - start))
file_sizes["proving.key"] = get_file_size("proving.key")  # Private key
file_sizes["verification.key"] = get_file_size("verification.key")  # Verification key
print("==== ZoKrates Setup ====")
print("Output:", result_setup.stdout)
if result_setup.stderr:
    print("Error:", result_setup.stderr)

# Step 2: Compute the witness
print("\n[Stage: Compute Witness] Computing the witness from the input data...")
start = time.time()
result_compute = subprocess.run(
    [
        "zokrates", "compute-witness",
        "--abi", "--stdin",
    ],
    input=zokrates_input_json,
    text=True,
    capture_output=True
)
end = time.time()
command_times.append(("Compute Witness", end - start))
file_sizes["witness"] = get_file_size("witness")
print("==== ZoKrates Compute Witness ====")
print("Output:", result_compute.stdout)
if result_compute.stderr:
    print("Error:", result_compute.stderr)
else:
    print("Witness computed successfully.")

# Step 3: Generate proof
print("\n[Stage: Generate Proof] Generating the proof using the proving key...")
start = time.time()
result_proof = subprocess.run(
    [
        "zokrates", "generate-proof",
    ],
    text=True,
    capture_output=True
)
end = time.time()
command_times.append(("Generate Proof", end - start))
file_sizes["proof.json"] = get_file_size("proof.json")
print("==== ZoKrates Generate Proof ====")
print("Output:", result_proof.stdout)
if result_proof.stderr:
    print("Error:", result_proof.stderr)
else:
    print("Proof generated successfully.")

# Step 4: Verify proof
print("\n[Stage: Verify Proof] Verifying the generated proof...")
start = time.time()
result_verify = subprocess.run(
    [
        "zokrates", "verify",
    ],
    text=True,
    capture_output=True
)
end = time.time()
command_times.append(("Verify Proof", end - start))
print("==== ZoKrates Verify Proof ====")
print("Output:", result_verify.stdout)
if result_verify.stderr:
    print("Error:", result_verify.stderr)
else:
    print("Proof verified successfully.")

# Step 5: Export verifier contract
print("\n[Stage: Export Verifier] Exporting the verifier smart contract...")
start = time.time()
result_export = subprocess.run(
    ["zokrates", "export-verifier"],
    text=True,
    capture_output=True
)
end = time.time()
command_times.append(("Export Verifier", end - start))
file_sizes["verifier.sol"] = get_file_size("verifier.sol")
print("==== ZoKrates Export Verifier ====")
print("Output:", result_export.stdout)
if result_export.stderr:
    print("Error:", result_export.stderr)
else:
    print("Verifier contract exported successfully.")

# save command execution times and file sizes to a CSV file
csv_file_name = f"{N}_signatures.csv"
with open(csv_file_name, mode="w", newline="") as csv_file:
    csv_writer = csv.writer(csv_file)
    csv_writer.writerow(["Type", "Name", "Value"])
    for stage, duration in command_times:
        csv_writer.writerow(["Execution Time", stage, f"{duration:.2f} seconds"])
    for file_name, file_size in file_sizes.items():
        csv_writer.writerow(["File Size", file_name, file_size])


# CONVERT [PROOF.JSON] TO REMIX-INTERFACE FORMAT
proof_file = "proof.json"
tester_file = "remix_test_params.json"
create_tester_json(proof_file, tester_file)


# cleanup script
print("\n[Stage: Cleanup] Cleaning up ZoKrates files...")
cleanup_script = "./remove_zokrates_files.sh"
try:
    subprocess.run([cleanup_script], check=True)
    print("Cleanup completed successfully.")
except subprocess.CalledProcessError as e:
    print(f"Error occurred during cleanup: {e}")

print(f"\nResults saved to {csv_file_name}")