#!/usr/bin/env python3

import os
import pickle
import unittest
from messengerClient import (
    MessengerClient
)
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes

def generate_p384_key_pair():
    secret_key = ec.generate_private_key(ec.SECP384R1())
    public_key = secret_key.public_key()
    return (secret_key, public_key)

def sign_with_ecdsa(secret_key, data):
    signature = secret_key.sign(data, ec.ECDSA(hashes.SHA256()))
    return signature

class TestMessenger(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Par ključeva koji će CA koji će se koristiti za potpisivanje i verificiranje
        # generiranih certifikacijskih objekata. CA će potpisati svaki generirani
        # certifikacijski objekt prije nego što ga proslijedi drugim klijentima
        # koji će ga onda verificirati.
        cls.ca_secret_key, cls.ca_public_key = generate_p384_key_pair()

    def test_import_certificate_without_error(self):

        alice = MessengerClient('Alice', self.ca_public_key)
        bob = MessengerClient('Bob', self.ca_public_key)

        alice_cert = alice.generate_certificate()
        bob_cert = bob.generate_certificate()

        alice_cert_sign = sign_with_ecdsa(
            self.ca_secret_key,
            pickle.dumps(alice_cert)
        )
        bob_cert_sign = sign_with_ecdsa(
            self.ca_secret_key,
            pickle.dumps(bob_cert)
        )

        alice.receive_certificate(bob_cert, bob_cert_sign)
        bob.receive_certificate(alice_cert, alice_cert_sign)

if __name__ == "__main__":
    unittest.main(verbosity=2)
