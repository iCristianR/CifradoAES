
import base64

# Tabla sbox directa
sbox = (
    0x63, 0x7c, 0xd7, 0x44, 0x02, 0x81, 0xf0, 0xf3, 0xe8, 0x13, 0x12, 0x24, 0x91, 0x74, 0x10, 0xc2,
    0x9d, 0x2e, 0x60, 0x28, 0xe0, 0xf4, 0xfb, 0x6e, 0x1a, 0xda, 0xd3, 0x61, 0xe1, 0xa1, 0xb3, 0x7f,
    0x27, 0x45, 0xfe, 0x09, 0xe2, 0xc3, 0xc6, 0x0f, 0x99, 0xce, 0xa8, 0x26, 0x14, 0xb0, 0xde, 0x0a,
    0xe4, 0xcf, 0xbf, 0x58, 0x3b, 0xa5, 0x62, 0x1c, 0x19, 0xb5, 0x39, 0x46, 0x30, 0x90, 0x56, 0x3c,
    0x7a, 0xa9, 0x70, 0x35, 0xad, 0x7b, 0x6d, 0x32, 0x98, 0x41, 0x33, 0x03, 0x8a, 0x52, 0x55, 0xc9,
    0x1e, 0xd6, 0x8e, 0xf8, 0xbd, 0xa7, 0xfa, 0x88, 0xd8, 0x64, 0xb1, 0x6c, 0x86, 0x67, 0xec, 0x21,
    0xa0, 0x50, 0x0e, 0x53, 0x0d, 0xba, 0xc5, 0x6a, 0x4f, 0x47, 0x00, 0x1d, 0xe3, 0xfd, 0xdc, 0xfc,
    0x65, 0xbb, 0x08, 0xe5, 0x4e, 0x57, 0xf1, 0xff, 0xca, 0x48, 0x9a, 0x2a, 0xf9, 0x72, 0xf7, 0x84,
    0xef, 0x3e, 0x3d, 0x07, 0xea, 0x2f, 0x73, 0x93, 0x04, 0xaf, 0x6f, 0x85, 0x5f, 0x76, 0xcb, 0x23,
    0x9e, 0x1f, 0x49, 0xd4, 0x4b, 0xcc, 0x68, 0x69, 0x97, 0x17, 0xc0, 0xa3, 0x78, 0xd1, 0x36, 0xa2,
    0xdd, 0xd9, 0x82, 0x8d, 0xae, 0x8c, 0x95, 0x3f, 0x0c, 0x9b, 0x01, 0x4a, 0x94, 0x8b, 0x96, 0x06,
    0xbe, 0x16, 0xdb, 0xbc, 0x31, 0x92, 0xdf, 0xc4, 0xaa, 0x89, 0x5a, 0x80, 0xa4, 0xb6, 0x42, 0xc8,
    0xb9, 0xf6, 0xc1, 0x25, 0xd5, 0x51, 0x40, 0x77, 0x54, 0x7e, 0xb4, 0x9c, 0x0b, 0x1b, 0xe7, 0x6b,
    0x75, 0x05, 0x71, 0xd0, 0xe9, 0x2b, 0x5c, 0x5e, 0x18, 0xd2, 0x2c, 0x7d, 0x87, 0x43, 0xac, 0x37,
    0x5b, 0x5d, 0x34, 0xa6, 0xed, 0x83, 0x20, 0x4d, 0xf5, 0x8f, 0x79, 0x4c, 0x11, 0x66, 0x2d, 0xe6,
    0xb7, 0x59, 0xcd, 0x22, 0x9f, 0x38, 0xc7, 0xb2, 0x15, 0x3a, 0xeb, 0xee, 0x29, 0xb8, 0xab, 0xf2
)

# Tabla sbox inversa
sbox_inv = (
    0x6a, 0xaa, 0x04, 0x4b, 0x88, 0xd1, 0xaf, 0x83, 0x72, 0x23, 0x2f, 0xcc, 0xa8, 0x64, 0x62, 0x27,
    0x0e, 0xec, 0x0a, 0x09, 0x2c, 0xf8, 0xb1, 0x99, 0xd8, 0x38, 0x18, 0xcd, 0x37, 0x6b, 0x50, 0x91,
    0xe6, 0x5f, 0xf3, 0x8f, 0x0b, 0xc3, 0x2b, 0x20, 0x13, 0xfc, 0x7b, 0xd5, 0xda, 0xee, 0x11, 0x85,
    0x3c, 0xb4, 0x47, 0x4a, 0xe2, 0x43, 0x9e, 0xdf, 0xf5, 0x3a, 0xf9, 0x34, 0x3f, 0x82, 0x81, 0xa7,
    0xc6, 0x49, 0xbe, 0xdd, 0x03, 0x21, 0x3b, 0x69, 0x79, 0x92, 0xab, 0x94, 0xeb, 0xe7, 0x74, 0x68,
    0x61, 0xc5, 0x4d, 0x63, 0xc8, 0x4e, 0x3e, 0x75, 0x33, 0xf1, 0xba, 0xe0, 0xd6, 0xe1, 0xd7, 0x8c,
    0x12, 0x1b, 0x36, 0x00, 0x59, 0x70, 0xed, 0x5d, 0x96, 0x97, 0x67, 0xcf, 0x5b, 0x46, 0x17, 0x8a,
    0x42, 0xd2, 0x7d, 0x86, 0x0d, 0xd0, 0x8d, 0xc7, 0x9c, 0xea, 0x40, 0x45, 0x01, 0xdb, 0xc9, 0x1f,
    0xbb, 0x05, 0xa2, 0xe5, 0x7f, 0x8b, 0x5c, 0xdc, 0x57, 0xb9, 0x4c, 0xad, 0xa5, 0xa3, 0x52, 0xe9,
    0x3d, 0x0c, 0xb5, 0x87, 0xac, 0xa6, 0xae, 0x98, 0x48, 0x28, 0x7a, 0xa9, 0xcb, 0x10, 0x90, 0xf4,
    0x60, 0x1d, 0x9f, 0x9b, 0xbc, 0x35, 0xe3, 0x55, 0x2a, 0x41, 0xb8, 0xfe, 0xde, 0x44, 0xa4, 0x89,
    0x2d, 0x5a, 0xf7, 0x1e, 0xca, 0x39, 0xbd, 0xf0, 0xfd, 0xc0, 0x65, 0x71, 0xb3, 0x54, 0xb0, 0x32,
    0x9a, 0xc2, 0x0f, 0x25, 0xb7, 0x66, 0x26, 0xf6, 0xbf, 0x4f, 0x78, 0x8e, 0x95, 0xf2, 0x29, 0x31,
    0xd3, 0x9d, 0xd9, 0x1a, 0x93, 0xc4, 0x51, 0x02, 0x58, 0xa1, 0x19, 0xb2, 0x6e, 0xa0, 0x2e, 0xb6,
    0x14, 0x1c, 0x24, 0x6c, 0x30, 0x73, 0xef, 0xce, 0x08, 0xd4, 0x84, 0xfa, 0x5e, 0xe4, 0xfb, 0x80,
    0x06, 0x76, 0xff, 0x07, 0x15, 0xe8, 0xc1, 0x7e, 0x53, 0x7c, 0x56, 0x16, 0x6f, 0x6d, 0x22, 0x77
)

def key_expansion(key):
    # Valores de la constante de ronda
    rcon = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)

    # Convertir el arreglo de hexadecimales a una lista de bytes
    round_keys = [int(b, 16) for b in key]
    
    # Llena la lista de subclaves
    for i in range(4, 44):
        # Última subclave
        temp = round_keys[(i - 1) * 4:i * 4]

        if i % 4 == 0:
            # Rotar palabra y aplicar S-box a todos los bytes
            temp = [sbox[b] for b in [temp[1], temp[2], temp[3], temp[0]]]
            temp[0] ^= rcon[i // 4 - 1]

        for j in range(4):
            # Genera una nueva subclave a partir de la anterior
            round_keys.extend([round_keys[(i - 4) * 4 + j] ^ temp[j]])

    return round_keys

def add_round_key(state, round_key):
    # Operación XOR entre el estado y la clave de ronda
    return [state[i] ^ round_key[i] for i in range(16)]

def inv_sub_bytes(state):
    # Sustituye cada byte del estado por su valor en la tabla sbox inversa
    return [sbox_inv[byte] for byte in state]

def sub_bytes(state):
    # Sustituye cada byte del estado por su valor en la tabla sbox
    return [sbox[byte] for byte in state]

def shift_rows(state):
    # Reorganiza las filas del estado
    shift_rows_table = [
        [0, 1, 2, 3],
        [5, 6, 7, 4],
        [10,11, 8, 9],
        [15, 12, 13, 14]
    ]
    # Matriz de 16 elementos vacía para almacenar el nuevo estado
    new_state = [0] * 16

    for row in range(4):
        for col in range(4):
            # Obtener posición en la nueva matriz a partir de la tabla shift_rows_table
            new_state[row * 4 + col] = state[shift_rows_table[row][col]]

    return new_state

def inv_shift_rows(state):
    # Reorganiza las filas del estado (inverso de shift_rows)
    shift_rows_table = [
        [0, 1, 2, 3],
        [7, 4, 5, 6],
        [10, 11, 8, 9],
        [13, 14, 15, 12]
    ]
    # Matriz de 16 elementos vacía para almacenar el nuevo estado
    new_state = [0] * 16

    for row in range(4):
        for col in range(4):
            # Obtener posición en la nueva matriz a partir de la tabla shift_rows_table
            new_state[row * 4 + col] = state[shift_rows_table[row][col]]

    return new_state

def gf_multiply(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            # Si el bit bajo de 'b' es 1, se suma 'a' a 'p' usando XOR
            p ^= a
        carry = a & 0x80 # Verificamos si el bit más alto de 'a' es 1
        a <<= 1 # Desplazamos 'a' un bit a la izquierda
        if carry:
            # Aplicamos reducción utilizando el polinomio irreducible
            a ^= 0x1C3  # x^8 + x^7 + x^6 + x^5 + x^4 + x + 1 
        b >>= 1 # Desplazamos 'b' un bit a la derecha
    return p
    
def mix_columns(state):
    # Mezcla los bytes dentro de cada columna del estado
    mix_columns_table = [
        [0x02, 0x03, 0x01, 0x01],
        [0x01, 0x02, 0x03, 0x01],
        [0x01, 0x01, 0x02, 0x03],
        [0x03, 0x01, 0x01, 0x02]
    ]
    # Matriz de 16 elementos vacía para almacenar el nuevo estado
    new_state = [0] * 16
    
    for col in range(4):
        for row in range(4):
            val = 0
            for i in range(4):
                # Multiplicación en el campo Galois y XOR
                val ^= gf_multiply(mix_columns_table[row][i], state[col * 4 + i])
            # Almacena el resultado de la mezcla en la nueva matriz
            new_state[col * 4 + row] = val
            
    return new_state

def inv_mix_columns(state):
    # Mezcla los bytes dentro de cada columna del estado (inverso de mix_columns)
    inv_mix_columns_table = [
        [0x0E, 0x0B, 0x0D, 0x09],
        [0x09, 0x0E, 0x0B, 0x0D],
        [0x0D, 0x09, 0x0E, 0x0B],
        [0x0B, 0x0D, 0x09, 0x0E]
    ]
    # Matriz de 16 elementos vacía para almacenar el nuevo estado
    new_state = [0] * 16

    for col in range(4):
        for row in range(4):
            val = 0
            for i in range(4):
                # Multiplicación en el campo Galois y XOR
                val ^= gf_multiply(inv_mix_columns_table[row][i], state[col * 4 + i])
            # Almacena el resultado de la mezcla en la nueva matriz
            new_state[col * 4 + row] = val

    return new_state

def aes_encrypt(state, round_keys):
    # Convertir el arreglo de hexadecimales a una lista de bytes
    state = [int(b, 16) for b in state]
    
    # Ronda inicial
    print("\nRonda 0:")
    print("Estado inicial:", bytes_to_hex_string(state))
    state = add_round_key(state, round_keys[:16])
    print("Después de AddRoundKey:", bytes_to_hex_string(state))

    # 9 rondas principales
    for i in range(1, 10):
        print(f"\nRonda {i}:")
        state = sub_bytes(state)
        print("Después de SubBytes:", bytes_to_hex_string(state))
        state = shift_rows(state)
        print("Después de ShiftRows:", bytes_to_hex_string(state))
        state = mix_columns(state)
        print("Después de MixColumns:", bytes_to_hex_string(state))
        state = add_round_key(state, round_keys[i * 16:(i + 1) * 16])
        print("Después de AddRoundKey:", bytes_to_hex_string(state))

    # Ronda final
    print("\nRonda 10:")
    state = sub_bytes(state)
    print("Después de SubBytes:", bytes_to_hex_string(state))
    state = shift_rows(state)
    print("Después de ShiftRows:", bytes_to_hex_string(state))
    state = add_round_key(state, round_keys[10 * 16:])
    print("Después de AddRoundKey:", bytes_to_hex_string(state))

    return state

def aes_decrypt(ciphertext, round_keys):
    state = list(ciphertext)

    # Ronda inicial
    print("\nRonda 0:")
    print("Estado inicial:", bytes_to_hex_string(state))
    state = add_round_key(state, round_keys[10 * 16:])
    print("Después de AddRoundKey:", bytes_to_hex_string(state))
    
    # 9 rondas principales (en orden inverso)
    cont = 1
    for i in range(9, 0, -1):
        print(f"\nRonda {cont}:")
        state = inv_shift_rows(state)
        print("Después de InvShiftRows:", bytes_to_hex_string(state))
        state = inv_sub_bytes(state)
        print("Después de InvSubBytes:", bytes_to_hex_string(state))
        state = add_round_key(state, round_keys[i * 16:(i + 1) * 16])
        print("Después de AddRoundKey:", bytes_to_hex_string(state))
        state = inv_mix_columns(state)
        print("Después de InvMixColumns:", bytes_to_hex_string(state))
        cont += 1
    
    # Ronda final
    print("\nRonda 10:")
    state = inv_shift_rows(state)
    print("Después de InvShiftRows:", bytes_to_hex_string(state))
    state = inv_sub_bytes(state)
    print("Después de InvSubBytes:", bytes_to_hex_string(state))
    state = add_round_key(state, round_keys[:16])
    print("Después de AddRoundKey:", bytes_to_hex_string(state))

    return state
        
def bytes_to_hex_string(state):
    # Imprimir el estado en formato hexadecimal
    return ''.join(format(byte, '02x') for byte in state)

def pkcs7_pad(data, block_size):
    # Aplica el esquema de relleno PKCS7 a un bloque de datos para ajustar su longitud al tamaño de bloque deseado
    # El valor del byte sera la longitud de datos que faltan para ajustar
    data_length = len(data)
    if data_length % block_size == 0:
        return data  # No aplicar relleno si el bloque ya está completo
    
    padding_length = block_size - (data_length % block_size)
    padding = bytes([padding_length] * padding_length)

    return data + padding

if __name__ == "__main__":
    plaintext = "Hola mundo!"
    key = "SecretkeyAes128$"

    ba_text = pkcs7_pad(bytearray(plaintext.encode('utf-8')), 16)
    ba_key = pkcs7_pad(bytearray(key.encode('utf-8')), 16)

    list_hex_text = [hex(byte) for byte in ba_text]
    list_hex_key = [hex(byte) for byte in ba_key]

    print("\n///--- Expansion de llaves: ---///\n")
    round_keys = key_expansion(list_hex_key)
    for i in range(11):
        print(f"{i}: | {bytes_to_hex_string(round_keys[i * 16:(i + 1) * 16])}")

    print("\n///--- Cifrado ---///")
    cipher_bytes = aes_encrypt(list_hex_text, round_keys)
    cipher_base64 = base64.b64encode(bytes(cipher_bytes)).decode('utf-8')
    print("\nTexto cifrado:", cipher_base64)
    
    print("\n///--- Descifrado ---///")
    decipher_bytes = aes_decrypt(cipher_bytes, round_keys)
    decipher_text = bytearray(decipher_bytes).decode('utf-8')
    print("\nTexto descifrado:", decipher_text)
