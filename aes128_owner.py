
import base64

# Tabla sbox directa
sbox = (

)

# Tabla sbox inversa
sbox_inv = (

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
