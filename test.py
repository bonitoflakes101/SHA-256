

from src.sha256 import SHA256
from src.esha256 import ESHA256
from src.utils import hamming_distance

# Test a medical record
message = b"Patient: John Doe, DOB: 1980-01-15, Blood Type: O+"

sha = SHA256()
esha = ESHA256()

hash_sha = sha.hexdigest(message)
hash_esha = esha.hexdigest(message)

print("Medical Record Hash Test")
print("=" * 60)
print(f"Message: {message.decode()}")
print(f"\nSHA-256:  {hash_sha}")
print(f"ESHA-256: {hash_esha}")
print(f"\nDifferent: {hash_sha != hash_esha}")

# Compare bit difference
diff_bits = hamming_distance(
    bytes.fromhex(hash_sha),
    bytes.fromhex(hash_esha)
)
print(f"Bits different: {diff_bits}/256 ({diff_bits/256*100:.1f}%)")