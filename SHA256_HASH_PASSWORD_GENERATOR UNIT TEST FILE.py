import unittest
from hashlib import sha512
from SHA256_HASH_PASSWORD_GENERATOR import generate_hash  # Replace with your actual script name

class TestSHA256HashGenerator(unittest.TestCase):

    def test_generate_hash_valid_password(self):
        # Test with a valid password
        password = "password123"
        expected_hash = sha512(password.encode()).hexdigest()
        self.assertEqual(generate_hash(password), expected_hash)

    def test_generate_hash_empty_password(self):
        # Test with an empty password (should raise ValueError)
        with self.assertRaises(ValueError):
            generate_hash("")

    def test_generate_hash_special_characters(self):
        # Test with a password containing special characters
        password = "!@#$%^&*()_+"
        expected_hash = sha512(password.encode()).hexdigest()
        self.assertEqual(generate_hash(password), expected_hash)

    def test_generate_hash_long_password(self):
        # Test with a long password
        password = "a" * 1000  # A very long password (1000 characters of 'a')
        expected_hash = sha512(password.encode()).hexdigest()
        self.assertEqual(generate_hash(password), expected_hash)

if __name__ == "__main__":
    unittest.main()
