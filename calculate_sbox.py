
def galois_multiplication(a, b):
    p = 0
    hi_bit_set = 0
    for _ in range(8):
        if b & 1 == 1:
            p ^= a
        hi_bit_set = a & 0x80
        a <<= 1
        if hi_bit_set == 0x80:
            # a ^= 0x11b
            a ^= 0x1C3  # x^8 + x^7 + x^6 + x^5 + x^4 + x + 1 
        b >>= 1
    return p % 256

def galois_inverse(num):
    if num == 0:
        return 0
    for ext in range(256):
        if galois_multiplication(num, ext) == 1:
            return ext
    return 0

def sbox_transformation(byte):
    c = 0x63
    s_box_byte = byte
    for _ in range(4):
        s_box_byte = ((s_box_byte << 1) & 0xFF) | (s_box_byte >> 7)
        byte ^= s_box_byte
    return (byte ^ c) & 0xFF

print("SBOX")

def generate_sbox():
    sbox = []
    for byte in range(256):
        inverted = galois_inverse(byte)
        sbox.append(sbox_transformation(inverted))
    return sbox

sbox = generate_sbox()
for i in range(16):
    for j in range(16):
        hex_value = hex(sbox[i * 16 + j])[2:].zfill(2)
        print(f"0x{hex_value}, ", end="")
    print()

print("\nInverse SBOX")

def generate_inverse_sbox(sbox):
    inverse_sbox = [0] * 256
    for i, value in enumerate(sbox):
        inverse_sbox[value] = i
    return inverse_sbox

inverse_sbox = generate_inverse_sbox(sbox)
for i in range(16):
    for j in range(16):
        hex_value = hex(inverse_sbox[i * 16 + j])[2:].zfill(2)
        print(f"0x{hex_value}, ", end="")
    print()