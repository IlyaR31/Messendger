import random, math

def fast_modular_pow(A, k, m):
    R = 1

    while k > 0:
        if k % 2 != 0:
            R *= A
            R %= m
            k -= 1
        if k % 2 == 0:
            A **= 2
            A %= m
            k //= 2

    return R

def prime_test(p, tests=10):
    if p <= 1: return False
    if p == 2: return True
    for i in range(tests):
        while True:
            a = random.randint(2, p-1)
            if a % p != 0:
                break

        if fast_modular_pow(a, p-1, p) != 1:
            return False

    return True

def is_prime(p):
    if p <= 1: return False
    if p == 2: return True
    if p % 2 == 0: return False
    for i in range(3, int(math.sqrt(p)) + 1, 2):
        if p % i == 0:
            return False
    return True

def generate_prime(a, b):
    if a <= 1 or b <= 1:
        raise ValueError("A и B должжны быть 2 или больше")

    if a > b:
        a, b = b, a # На всякий случай

    while True:
        test = random.randint(a, b)

        if not prime_test(test):
            continue

        if is_prime(test):
            return test

def gcd(a, b):
    if b == 0:
        return a
    return gcd(b, a % b)

def extended_gcd(A, B):
    if B == 0:
        return 1, 0, A

    x1, y1, g = extended_gcd(B, A%B)
    return y1, (x1 - y1 * (A//B)), g

def calculate_e(phi):
    while True:
        prime = random.randint(2, phi-1)
        if gcd(phi, prime) == 1:
            return prime

def calculate_d(e, phi):
    x, y, g = extended_gcd(e, phi)
    assert g == 1
    return x % phi


def generate_keys(keysize=1024):
    p, q = generate_prime(2**(keysize-1), 2**keysize-1), generate_prime(2**(keysize-1), 2**keysize-1)
    N = p*q
    phiN = (p - 1) * (q - 1)

    e = calculate_e(phiN)
    d = calculate_d(e, phiN)
    return (e, N), (d, N)

def to_number(array_of_bytes):
    result = 0
    n = 1
    for byte in array_of_bytes:
        result += byte * n
        n <<= 8
    return result

def encrypt_number(A, PUBLIC_KEY):
    return fast_modular_pow(A, PUBLIC_KEY[0], PUBLIC_KEY[1])

def decrypt_number(A, PRIVATE_KEY):
    return fast_modular_pow(A, PRIVATE_KEY[0], PRIVATE_KEY[1])

def from_number(number, length=None):
    if length is None:
        length = -1
    result = b""

    while number > 0:
        result += (number % 256).to_bytes(1, "big")
        number >>= 8
        length -= 1

    if length > 0:
        result += ("\x00" * length).encode("utf-8")
    return result

def split_bytes(data, max_length=128):
    for b in range(0, len(data), max_length):
        yield data[b:b + max_length]

def encrypt(data, PUBLIC_KEY):
    return fast_modular_pow(to_number(data), PUBLIC_KEY[0], PUBLIC_KEY[1])

def decrypt(data, PRIVATE_KEY, length=None):
    return from_number(fast_modular_pow(data, PRIVATE_KEY[0], PRIVATE_KEY[1]), length)

def encrypt_data(data, PUBLIC_KEY):
    max_length = max(1, (PUBLIC_KEY[1].bit_length() - 1) // 8)
    result = []
    for d in split_bytes(data, max_length=max_length):
        e = encrypt(d, PUBLIC_KEY)
        result.append((len(d), e))
    return result


def decrypt_data(data, PRIVATE_KEY):
    result = b""
    for length, d in data:
        result += decrypt(d, PRIVATE_KEY, length=length)
    return result
