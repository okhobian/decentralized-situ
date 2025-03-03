import json

# CONVERT [PROOF.JSON] TO REMIX-INTERFACE FORMAT
proof_file = "proof.json"
tester_file = "tester.json"

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

create_tester_json(proof_file, tester_file)