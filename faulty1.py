import random
import numpy as np

# Define S-box (substitution box)
def s_box(input_bits):
    sbox = {
        0x0: 0xE, 0x1: 0x4, 0x2: 0xD, 0x3: 0x1,
        0x4: 0x2, 0x5: 0xF, 0x6: 0xB, 0x7: 0x8,
        0x8: 0x3, 0x9: 0xA, 0xA: 0x6, 0xB: 0xC,
        0xC: 0x5, 0xD: 0x9, 0xE: 0x0, 0xF: 0x7
    }
    return sbox[input_bits]

# Reverse S-box
def reverse_s_box(output_bits):
    rsbox = {v: k for k, v in {
        0x0: 0xE, 0x1: 0x4, 0x2: 0xD, 0x3: 0x1,
        0x4: 0x2, 0x5: 0xF, 0x6: 0xB, 0x7: 0x8,
        0x8: 0x3, 0x9: 0xA, 0xA: 0x6, 0xB: 0xC,
        0xC: 0x5, 0xD: 0x9, 0xE: 0x0, 0xF: 0x7
    }.items()}
    return rsbox[output_bits]

# Generate random key
def generate_key():
    return [random.randint(0, 15) for _ in range(4)]  # 4 nibbles (16-bit key)

# Encrypt function for Toy Cipher
def encrypt(plaintext, key):
    state = plaintext ^ key[0]
    state = s_box(state)
    state ^= key[1]
    return state

# Decrypt function for Toy Cipher
def decrypt(ciphertext, key):
    state = ciphertext ^ key[1]
    state = reverse_s_box(state)
    state ^= key[0]
    return state

# Introduce a fault in a single bit
def introduce_fault(state):
    bit_position = random.randint(0, 3)  # Select random bit position (0-3)
    return state ^ (1 << bit_position)

# Find fault location and candidate keys
def fault_analysis(ciphertext, faulty_ciphertext, key):
    original_decrypted = decrypt(ciphertext, key)
    faulty_decrypted = decrypt(faulty_ciphertext, key)
    fault_location = original_decrypted ^ faulty_decrypted
    
    candidate_keys = []
    for candidate in range(16):
        if s_box(original_decrypted ^ candidate) ^ s_box(faulty_decrypted ^ candidate) == fault_location:
            candidate_keys.append(candidate)
    return fault_location, candidate_keys

# Main simulation
def main():
    plaintext = random.randint(0, 15)  # Random 4-bit plaintext
    key = generate_key()
    
    print("Generated Key:", key)
    print("Plaintext:", format(plaintext, '04b'))

    # Encrypt plaintext
    ciphertext = encrypt(plaintext, key)
    print("Ciphertext:", format(ciphertext, '04b'))

    # Introduce fault in last round
    faulty_ciphertext = introduce_fault(ciphertext)
    print("Faulty Ciphertext:", format(faulty_ciphertext, '04b'))

    # Fault analysis
    fault_location, candidate_keys = fault_analysis(ciphertext, faulty_ciphertext, key)
    print("Fault Location (bit difference):", format(fault_location, '04b'))
    print("Candidate Keys:", candidate_keys)

    # Verify if original key is among candidates
    if key[1] in candidate_keys:
        print("Original key found in candidates.")
    else:
        print("Original key NOT found in candidates.")

if __name__ == "__main__":
    main()
