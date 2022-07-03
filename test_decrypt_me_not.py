import decrypt_me_not
import os
import tempfile
import time
import unittest


class TestDecryptMeNot(unittest.TestCase):
    def test_base_256_conversion(self):
        for num_base_10 in range(1_000_000):
            num_base_256 = decrypt_me_not.base_10_to_base_n(num_base_10, 256)
            self.assertEqual(num_base_10, base_256_to_base_10(num_base_256))

    def test_end_to_end(self):
        with tempfile.TemporaryDirectory() as dnm_base_dir:
            test_file_contents = os.urandom(2000)
            plaintext_file_path = dnm_base_dir + "/test.txt"
            with open(plaintext_file_path, 'wb') as test_file:
                test_file.write(test_file_contents)

            # Encrypt and decrypt test file.
            encrypted_file_path = dnm_base_dir + "/encrypted_test.txt"
            decrypted_file_path = dnm_base_dir + "/decrypted_test.txt"
            decrypt_me_not.encrypt(plaintext_file_path, "60s", encrypted_file_path)

            decrypt_start_time = time.time()
            decrypt_me_not.decrypt(encrypted_file_path, decrypted_file_path)
            decrypt_duration = time.time() - decrypt_start_time
            # There is a ~66% chance we're within 1 stddev of the 60s mean (+-11s)
            # There is a ~95% chance we're within 2 stddev of the 60s mean (+-22s)
            # stddevs = [(abs(60 - sum([random.random() * 12 for _ in range(10)]))) / 10.9544 for _ in range(100_000)]
            # sum([1 if stddev > 2 else 0 for stddev in stddevs]) / len(stddevs)
            self.assertGreater(decrypt_duration, 60-22, "decryption too fast, rerun test (2.5% chance)")
            self.assertLess(decrypt_duration, 60+22, "decryption too slow, rerun test (2.5% chance)")

            # Verify decrypted contents match.
            with open(decrypted_file_path, 'rb') as decrypted_file:
                decrypted_contents = decrypted_file.read()
            self.assertEqual(test_file_contents, decrypted_contents)


def base_256_to_base_10(num_base_256: bytes) -> int:
    num_base_10 = 0
    multiplier = 1
    for bit in num_base_256:
        num_base_10 += bit * multiplier
        multiplier *= 256
    return num_base_10
