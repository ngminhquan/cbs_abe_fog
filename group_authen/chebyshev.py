
#integer to byestring function
def int_to_bytes(n):
    if n == 0:
        return b'\x00'
    byte_size = (n.bit_length() + 7) // 8  # Calculate the required byte size
    byte_order = 'big'  # Use 'big' or 'little' endian

    # Convert the integer to bytes
    bytes_data = n.to_bytes(byte_size, byte_order)
    return bytes_data


def chebyshev(n, x, m):
    if n == 0:
        return 1
    elif n == 1:
        return x % m
    else:
        e = n - 1
        a11, a12, a21, a22 = 1, 0, 0, 1
        s11, s12, s21, s22 = 0, 1, -1, (2 * x)
        
        while e > 1:
            if e % 2 == 1:
                t1 = (a11 * s11 + a12 * s21) % m
                a12 = (a11 * s12 + a12 * s22) % m
                a11 = t1
                t2 = (a21 * s11 + a22 * s21) % m
                a22 = (a21 * s12 + a22 * s22) % m
                a21 = t2
            t1 = s11 + s22
            t2 = s12 * s21
            s11 = (s11 ** 2 + t2) % m
            s12 = (s12 * t1) % m
            s21 = (s21 * t1) % m
            s22 = (s22 ** 2 + t2) % m
            e //=2
        
        t1 = (a21 * s11 + a22 * s21) % m
        t2 = (a21 * s12 + a22 * s22) % m
        return (t1 + t2 * x) % m
    
def xor(a: bytes, b: bytes) -> bytes:
    return bytes([x ^ y for x, y in zip(a, b)])