import unittest
import decrypt_me_not


class TestDecryptMeNot(unittest.TestCase):
    def test_base_256_conversion(self):
        for num_base_10 in range(1_000_000):
            num_base_256 = decrypt_me_not.base_10_to_base_n(num_base_10, 256)
            self.assertEqual(num_base_10, base_256_to_base_10(num_base_256))


def base_256_to_base_10(num_base_256: bytes) -> int:
    num_base_10 = 0
    multiplier = 1
    for bit in num_base_256:
        num_base_10 += bit * multiplier
        multiplier *= 256
    return num_base_10
