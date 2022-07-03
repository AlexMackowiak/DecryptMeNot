import base64
from cryptography.fernet import Fernet, InvalidToken
from pytimeparse.timeparse import timeparse
import random
import time
import typer

"""
Base algorithm:
1. Get decryption time for a given message size
    a. One problem: decryption time does not scale linearly with message size
        i. Solution: store an extra line in the file which can be used to check against 
        ii. Solution 2: Time decryptions for the given message length at each key <--- Just go with this for now
2. For each of 50 keys:
    a. Calculate num average decryptions for current message size to achieve an average of 1/50th of total time
    b. Take a random value from a keyspace large enough to average to 1/50th of the total time
    c. Use the encoded value as the key for the current round
"""
# Finding 1: timing IS incredibly similar for the exact same encrypted input
# Finding 2: size explodes exponentially with each key, at least 1.33x per key. At 10 keys will 17x file size
# Finding 3: Message contents do not affect decryption speed
# Finding 4: Encrypting and decrypting key values _very slightly_ affect decryption speed
# Finding 5: Effectively, encrypted message length is the only variable that matters in deriving decryption speed

app = typer.Typer()

KEY_NUMBER_BASE = 256
FERNET_KEY_LEN = 32
TOTAL_NUM_KEYS = 10


# TODO: add password option
@app.command()
def encrypt(file_path_to_encrypt: str, duration_to_decrypt: str):
    secs_to_decrypt = parse_secs_to_decrypt(duration_to_decrypt)
    with open(file_path_to_encrypt, 'rb') as file_to_encrypt:
        file_contents = file_to_encrypt.read()

    keys = []
    decrypt_secs_per_key = secs_to_decrypt / TOTAL_NUM_KEYS
    encrypted_file_contents = file_contents
    for _ in range(TOTAL_NUM_KEYS):
        decryptions_per_sec = find_message_decrypt_time(encrypted_file_contents)
        print(decryptions_per_sec)
        num_decrypts_for_target_time = int(decrypt_secs_per_key * decryptions_per_sec)
        keyspace_size = 2 * num_decrypts_for_target_time  # Uniform distribution, average to find key is 1/2 keyspace.

        # Represent keys as a 32-bit integer with bits in number base 256.
        random_key_base_10 = random.randint(0, keyspace_size)
        base_256_key = base_10_to_base_n(random_key_base_10, KEY_NUMBER_BASE)
        print(KEY_NUMBER_BASE, keyspace_size, random_key_base_10)

        # Base64 encode the key and use it to encrypt.
        fernet_encoded_random_key = base64.urlsafe_b64encode(base_256_key)
        encrypted_file_contents = Fernet(fernet_encoded_random_key).encrypt(encrypted_file_contents)
        keys.append(fernet_encoded_random_key)

    # Sanity check that we can decrypt the file contents using known keys.
    decrypted = encrypted_file_contents
    for known_key in reversed(keys):
        decrypted = Fernet(known_key).decrypt(decrypted)
    assert file_contents == decrypted

    # Write encrypted file contents to new file.
    # TODO: Better file handling
    output_file_path = "dnm_encrypted_" + file_path_to_encrypt
    with open(output_file_path, 'wb') as output_file:
        output_file.write(encrypted_file_contents)


@app.command()
def decrypt(file_path_to_decrypt: str):
    with open(file_path_to_decrypt, 'rb') as file_to_decrypt:
        encrypted_file_contents = file_to_decrypt.read()

    start_time = time.time()
    for i in range(TOTAL_NUM_KEYS):
        print(i, time.time() - start_time)
        curr_key = bytearray(FERNET_KEY_LEN)
        while True:
            maybe_decryptor = Fernet(base64.urlsafe_b64encode(curr_key))
            try:
                encrypted_file_contents = maybe_decryptor.decrypt(encrypted_file_contents)
                break
            except InvalidToken:
                pass
            inc_base256_bytes_key(curr_key)

    # TODO: actually write file to disk
    print("Elapsed time:", time.time() - start_time)
    print(encrypted_file_contents)


def parse_secs_to_decrypt(duration_to_decrypt: str) -> int:
    secs_to_decrypt = timeparse(duration_to_decrypt)
    if secs_to_decrypt is None:
        raise ValueError(f"could not parse duration \"{duration_to_decrypt}\" like 9h5m30s")
    return int(secs_to_decrypt)


# TODO: consolidate this with actual decryption implementation
# Fake encrypt the message and time how long it would take to decrypt at the encrypted message size.
def find_message_decrypt_time(file_contents: bytes) -> float:
    random_encrypt_key = Fernet.generate_key()
    fake_encrypted_file = Fernet(random_encrypt_key).encrypt(file_contents)

    num_failed_decryptions = 0
    curr_key = bytearray(FERNET_KEY_LEN)
    duration_secs = 5

    start_time = time.time()
    while time.time() < (start_time + duration_secs):
        invalid_decryptor = Fernet(base64.urlsafe_b64encode(curr_key))
        try:
            invalid_decryptor.decrypt(fake_encrypted_file)
        except InvalidToken:
            pass
        num_failed_decryptions += 1
        inc_base256_bytes_key(curr_key)
    return num_failed_decryptions / duration_secs


def inc_base256_bytes_key(curr_key: bytearray):
    inc_index = 0
    while inc_index < len(curr_key) and (curr_key[inc_index] == (KEY_NUMBER_BASE - 1)):
        curr_key[inc_index] = 0
        inc_index += 1
    curr_key[inc_index] += 1


def base_10_to_base_n(base_10_num: int, base_n: int) -> bytes:
    bit_index = 0
    curr_divisor = 1
    while curr_divisor < base_10_num:
        curr_divisor *= base_n
        bit_index += 1
    assert 0 <= bit_index < FERNET_KEY_LEN
    if curr_divisor > base_10_num:
        curr_divisor //= base_n
        bit_index -= 1

    base_n_num = bytearray(FERNET_KEY_LEN)
    while base_10_num > 0:
        num_divides_for_index = base_10_num // curr_divisor
        base_n_num[bit_index] = num_divides_for_index
        base_10_num -= curr_divisor * num_divides_for_index
        curr_divisor //= base_n
        bit_index -= 1
    assert base_10_num == 0
    return base_n_num


if __name__ == "__main__":
    app()
