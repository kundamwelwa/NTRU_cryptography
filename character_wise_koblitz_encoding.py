import math
import numpy as np # type: ignore

# Check if a number is prime
def is_prime(num):
    if num <= 1:
        return False
    for i in range(2, int(math.sqrt(num)) + 1):
        if num % i == 0:
            return False
    return True

# Find square root modulo p if it exists
def sq_root_mod_n(n, p):
    n = n % p
    for x in range(2, p):
        if (x * x) % p == n:
            return x
    return None  # Return None instead of 0 for better clarity

# Convert integer to ternary
def dec_ternary(n):
    if n == 0:
        return '0'
    nums = []
    while n:
        n, r = divmod(n, 3)
        nums.append(str(r))
    return ''.join(nums[::-1])

# Convert ternary back to integer
def ternary_dec(t):
    n = 0
    t = list(map(int, t[::-1]))  # Ensure input is a list of integers
    for i in range(len(t)):
        n += (3 ** i) * t[i]
    return n

# Cantor pairing function
def cantor_pair(k1, k2, safe=True):
    z = int(0.5 * (k1 + k2) * (k1 + k2 + 1) + k2)
    if safe and (k1, k2) != cantor_unpair(z):
        raise ValueError("Cantor Pairing failed for ({}, {})".format(k1, k2))
    return z

# Cantor unpairing function
def cantor_unpair(z):
    w = int((math.sqrt(8 * z + 1) - 1) / 2)
    t = (w * w + w) // 2
    y = int(z - t)
    x = int(w - y)
    return x, y

# Main encoding and decoding functions
def encode_message(plain_text, elliptic_a, elliptic_b, p, k=20):
    if not is_prime(p):
        raise ValueError("Parameter p must be prime.")
    
    ord_lst = [ord(ch) for ch in plain_text]
    encoded_points = []

    for m in ord_lst:
        for j in range(1, k):
            x_m = m * k + j
            n = pow(x_m, 3) + elliptic_a * x_m + elliptic_b
            y_m = sq_root_mod_n(n, p)
            if y_m is not None:
                encoded_points.append((x_m, y_m))
                break
        else:
            print(f"Character '{chr(m)}' could not be encoded on the elliptic curve.")

    return encoded_points

def decode_message(encoded_points, k=20):
    decoded_msg = []
    for x, _ in encoded_points:
        d = (x - 1) // k
        decoded_msg.append(chr(d))
    return ''.join(decoded_msg)

# Main script
plain_text = input("Enter Message: ")

print('Curve Parameters')
elliptic_a = int(input("Enter A: "))
elliptic_b = int(input("Enter B: "))
p = 751  # Example prime for field

encoded_points = encode_message(plain_text, elliptic_a, elliptic_b, p)
print('Encoded points generated:')
for x, y in encoded_points:
    print(f'({x}, {y}) - Ternary Encoding: {dec_ternary(cantor_pair(x, y))}')

decoded_message = decode_message(encoded_points)
print('\nDecoded Message:', decoded_message)

# Optional: Primitive point generation based on N
def primitive_start_point(N):
    decoded_points = []
    for i in range(-math.ceil(math.sqrt(N)), math.ceil(math.sqrt(N)) + 1):
        for j in range(-math.ceil(math.sqrt(N)), math.ceil(math.sqrt(N)) + 1):
            if i**2 + j**2 == N:
                decoded_points.append([j, i])
    return decoded_points

# Testing primitive_start_point function
N = 25
print("\nPrimitive points for N =", N)
print(primitive_start_point(N))

# Testing Cantor pairing and unpairing
for i in range(len(encoded_points)):
    x, y = encoded_points[i]
    cantor_val = cantor_pair(x, y)
    print(f"Point: ({x}, {y}) - Cantor Pairing: {cantor_val} - Ternary: {dec_ternary(cantor_val)}")
