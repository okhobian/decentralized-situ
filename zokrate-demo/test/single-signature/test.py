import hashlib
import json
import subprocess
from zokrates_pycrypto.eddsa import PrivateKey, PublicKey
from zokrates_pycrypto.field import FQ

def generate_signature_for_zokrates(pk, sig, msg):
    "Generates input arguments for verifyEddsa in the ZoKrates stdlib."
    sig_R, sig_S = sig

    # R: Signature point (x, y)
    R = [str(sig_R.x), str(sig_R.y)]
    
    # S: Scalar signature part
    S = str(sig_S)
    
    # A: Public key coordinates (x, y)
    A = [str(pk.p.x.n), str(pk.p.y.n)]

    # M0 and M1: Split the message into two 8-element arrays of 32-bit unsigned integers
    M0 = msg.hex()[:64]
    M1 = msg.hex()[64:]
    b0 = [str(int(M0[i:i+8], 16)) for i in range(0, len(M0), 8)]
    b1 = [str(int(M1[i:i+8], 16)) for i in range(0, len(M1), 8)]

    return [R, S, A, b0, b1]

if __name__ == "__main__":
    # Message and key generation
    raw_msg = "This is my secret message"
    msg = hashlib.sha512(raw_msg.encode("utf-8")).digest()

    # seeded private key for reproducibility
    key = FQ(1997011358982923168928344992199991480689546837621580239342656433234255379025)
    sk = PrivateKey(key)
    pk = PublicKey.from_private(sk)
    
    sig = sk.sign(msg)
    is_verified = pk.verify(sig, msg)
    print("Signature Verified:", is_verified)
    zokrates_input = generate_signature_for_zokrates(pk, sig, msg)
    zokrates_input_json = json.dumps(zokrates_input)
    witness_output_path = "witness.json"

    result = subprocess.run(
        [
            "zokrates", "compute-witness",
            "--abi", "--stdin",  # Use ABI encoding and stdin for input
            "--json",            # Output in JSON format
            "--output", witness_output_path  # Specify output witness file path
        ],
        input=zokrates_input_json,
        text=True,
        capture_output=True
    )

    print("ZoKrates Output:", result.stdout)
#######################################################################################################