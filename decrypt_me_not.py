import base64
from cryptography.fernet import Fernet, InvalidToken
from getpass import getpass, GetPassWarning
from pytimeparse.timeparse import timeparse
import random
import time
import typer
from typing import Optional, Union

# Experimental findings:
#  1. Timing is incredibly similar for the exact same encrypted input
#  2. Size explodes exponentially with each key, at least 1.33x per key. Using 10 keys will 17x file size
#  3. Message contents do not affect decryption speed
#  4. Encrypting and decrypting key values _very slightly_ affect decryption speed
#  5. Effectively, encrypted message length is the only variable that matters in deriving decryption speed

# Potential optimization: file sizes over 50KB are very easily predictable.
# The next level's encrypted file size and decryption speed will be ~4/3 the size of the current level.

KEY_NUMBER_BASE = 256
FERNET_KEY_LEN = 32
TOTAL_NUM_KEYS = 10

app = typer.Typer()
verbose = False


@app.command()
def encrypt(file_path_to_encrypt: str, duration_to_decrypt: str,
            output_path: Optional[str] = typer.Option('', '--out', '-o'),
            use_password: Optional[bool] = typer.Option(False, '--with-pass', '-p'),
            use_verbose: Optional[bool] = typer.Option(False, '--verbose', '-v')):
    if use_verbose:
        global verbose
        verbose = True
    secs_to_decrypt = parse_secs_to_decrypt(duration_to_decrypt)
    with open(file_path_to_encrypt, 'rb') as file_to_encrypt:
        file_contents = file_to_encrypt.read()
    password = prompt_user_password(use_password)

    keys = []
    decrypt_secs_per_key = secs_to_decrypt / TOTAL_NUM_KEYS
    encrypted_file_contents = file_contents
    for key_index in range(TOTAL_NUM_KEYS):
        vprint(f'Selecting encryption key {key_index+1}...')
        decryptions_per_sec = find_message_decrypt_time(encrypted_file_contents)
        vprint(f'At file size {len(encrypted_file_contents)}: {int(decryptions_per_sec)} decryptions/sec')
        num_decrypts_for_target_time = int(decrypt_secs_per_key * decryptions_per_sec)
        keyspace_size = 2 * num_decrypts_for_target_time  # Uniform distribution, average to find key is 1/2 keyspace.

        # Represent keys as a 32-bit integer with bits in number base 256.
        random_key_base_10 = random.randint(0, keyspace_size)
        base_256_key = base_10_to_base_n(random_key_base_10, KEY_NUMBER_BASE)
        vprint(f'Keyspace size {keyspace_size} will average {decrypt_secs_per_key} seconds to decrypt')
        vprint()

        # Base64 encode the key and use it to encrypt.
        fernet_encoded_random_key = base64.urlsafe_b64encode(base_256_key)
        encrypted_file_contents = Fernet(fernet_encoded_random_key).encrypt(encrypted_file_contents)
        keys.append(fernet_encoded_random_key)

    if use_password:
        password_key = base64.urlsafe_b64encode(password)
        encrypted_file_contents = Fernet(password_key).encrypt(encrypted_file_contents)
        keys.append(password_key)

    # Sanity check that we can decrypt the file contents using known keys.
    decrypted = encrypted_file_contents
    for known_key in reversed(keys):
        decrypted = Fernet(known_key).decrypt(decrypted)
    assert file_contents == decrypted

    # Write encrypted file contents to new file.
    if len(output_path) == 0:
        # TODO: Better file path handling
        output_path = 'dnm_encrypted_' + file_path_to_encrypt
    with open(output_path, 'wb') as output_file:
        output_file.write(encrypted_file_contents)
    vprint(f'File encrypted to {output_path}')


@app.command()
def decrypt(file_path_to_decrypt: str,
            output_path: Optional[str] = typer.Option('', '--out', '-o'),
            use_password: Optional[bool] = typer.Option(False, '--with-pass', '-p'),
            use_verbose: Optional[bool] = typer.Option(False, '--verbose', '-v')):
    if use_verbose:
        global verbose
        verbose = True
    with open(file_path_to_decrypt, 'rb') as file_to_decrypt:
        encrypted_file_contents = file_to_decrypt.read()

    if use_password:
        password = prompt_user_password(True)
        password_decryptor = Fernet(base64.urlsafe_b64encode(password))
        try:
            encrypted_file_contents = password_decryptor.decrypt(encrypted_file_contents)
        except InvalidToken:
            print('Wrong password, try again')
            exit(-1)

    start_time = time.time()
    for i in range(TOTAL_NUM_KEYS):
        no_end_time = time.time() + 1_000_000_000
        _, encrypted_file_contents = attempt_decrypt_until(encrypted_file_contents, no_end_time)
        vprint(f'Key {i+1}/{TOTAL_NUM_KEYS} found, elapsed time: {time.time() - start_time}')

    if len(output_path) == 0:
        # TODO: Better file path handling
        output_path = 'decrypted_' + file_path_to_decrypt
    with open(output_path, 'wb') as output_file:
        output_file.write(encrypted_file_contents)
    vprint(f'File decrypted to {output_path}')


def parse_secs_to_decrypt(duration_to_decrypt: str) -> int:
    secs_to_decrypt = timeparse(duration_to_decrypt)
    if secs_to_decrypt is None:
        raise ValueError(f'could not parse duration "{duration_to_decrypt}" like 9h5m30s')
    return int(secs_to_decrypt)


def prompt_user_password(use_password: bool) -> Union[None, bytes]:
    if not use_password:
        return None
    try:
        password = getpass('encrypted-file top-level password: ')
    except GetPassWarning:
        print('Could not securely prompt for password, exiting...')
        exit(-1)
        return None
    if len(password) == 0:
        print('Password cannot be empty')
        exit(-1)
    if len(password) > 32:
        print('Password must be 32 characters or less')
        exit(-1)
    # Pad password with 'A' characters because Fernet keys must be exactly length 32.
    return (password + ('A' * (FERNET_KEY_LEN - len(password)))).encode()


# Fake encrypt the message and time how long it would take to decrypt at the encrypted message size.
def find_message_decrypt_time(file_contents: bytes) -> float:
    timing_secs = 5
    while True:
        random_encrypt_key = Fernet.generate_key()
        fake_encrypted_file = Fernet(random_encrypt_key).encrypt(file_contents)
        decryptions_per_sec, decrypted_contents = attempt_decrypt_until(fake_encrypted_file, time.time() + timing_secs)
        if decrypted_contents is not None:
            # Retry timing in the astronomically unlikely case of having guessed the fake random key.
            continue
        return decryptions_per_sec


def attempt_decrypt_until(enc_file_contents: bytes, end_time: float) -> (float, bytes):
    curr_key = bytearray(FERNET_KEY_LEN)
    num_failed_decryptions = 0
    start_time = time.time()
    while time.time() < end_time:
        maybe_decryptor = Fernet(base64.urlsafe_b64encode(curr_key))
        try:
            return 0, maybe_decryptor.decrypt(enc_file_contents)
        except InvalidToken:
            num_failed_decryptions += 1
            inc_base256_bytes_key(curr_key)
    return num_failed_decryptions / (end_time - start_time), None


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


def vprint(*args, **kwargs):
    if verbose:
        print(*args, **kwargs)


if __name__ == '__main__':
    app()
