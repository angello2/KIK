#!/usr/bin/env python3

import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class MessengerClient:
    """ Messenger client class

        Feel free to modify the attributes and add new ones as you
        see fit.

    """

    def __init__(self, username, max_skip=10):
        """ Initializes a client

        Arguments:
        username (str) -- client name
        max_skip (int) -- Maximum number of message keys that can be skipped in
                          a single chain

        """
        self.username = username
        # Data regarding active connections.
        self.conn = {}
        # Maximum number of message keys that can be skipped in a single chain
        self.max_skip = max_skip
        self.salt = b"\xfd\xa4\xc3\x95\xd6\xaaE\x95\xb473\xc9\xec\x9c]\xb4"
        self.info = b"kik-lab1"

    def add_connection(self, username, CKs, CKr):
        """ Add a new connection

        Arguments:
        username (str) -- user that we want to talk to
        chain_key_send -- sending chain key (CKs) of the username
        chain_key_recv -- receiving chain key (CKr) of the username

        """
        self.conn[username] = {'CKs': CKs, 'CKr': CKr, 'Ns': 0, 'Nr': 0, 'MKSKIPPED': {}}

    def send_message(self, username, message):
        """ Send a message to a user

        Get the current sending key of the username, perform a symmetric-ratchet
        step, encrypt the message, update the sending key, return a header and
        a ciphertext.

        Arguments:
        username (str) -- user we want to send a message to
        message (str)  -- plaintext we want to send

        Returns a ciphertext and a header data (you can use a tuple object)

        """

        CKs_old = self.conn[username]['CKs']

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32 * 2,
            salt=self.salt,
            info=self.info,
        )
        key = hkdf.derive(CKs_old)
        chain_key = key[32:]
        message_key = key[:32]

        self.conn[username]['CKs'] = chain_key
        aesgcm = AESGCM(message_key)
        nonce = os.urandom(12)
        header = {'nonce': nonce, 'Ns': self.conn[username]['Ns']}
        self.conn[username]['Ns'] += 1
        return header, aesgcm.encrypt(nonce, bytes(message, 'utf-8'), None)

    def try_skipped_keys(self, username, message):
        header = message[0]
        if header['Ns'] in self.conn[username]['MKSKIPPED']:
            mk = self.conn[username]['MKSKIPPED'][header['Ns']]
            del self.conn[username]['MKSKIPPED'][header['Ns']]
            aesgcm = AESGCM(mk)
            return aesgcm.decrypt(header['nonce'], message[1], None).decode('utf-8')
        else:
            return None

    def skip_message_keys(self, username, until):
        if self.conn[username]['Nr'] + self.max_skip < until:
            raise Exception('Cannot skip more than' + self.max_skip + 'messages')
        else:
            while(self.conn[username]['Nr'] < until):
                hkdf = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32 * 2,
                    salt=self.salt,
                    info=self.info,
                )
                key = hkdf.derive(self.conn[username]['CKr'])
                chain_key = key[32:]
                message_key = key[:32]
                self.conn[username]['CKr'] = chain_key
                self.conn[username]['MKSKIPPED'][self.conn[username]['Nr']] = message_key
                self.conn[username]['Nr'] += 1

    def receive_message(self, username, message):
        """ Receive a message from a user

        Get the username connection data, check if the message is out-of-order,
        perform necessary symmetric-ratchet steps, decrypt the message and
        return the plaintext.

        Arguments:
        username (str) -- user who sent the message
        message        -- a ciphertext and a header data

        Returns a plaintext (str)

        """
        header = message[0]
        plaintext = self.try_skipped_keys(username, message)
        if plaintext != None:
            return plaintext
        self.skip_message_keys(username, header['Ns'])

        CKr_old = self.conn[username]['CKr']
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32 * 2,
            salt=self.salt,
            info=self.info,
        )
        key = hkdf.derive(CKr_old)
        chain_key = key[32:]
        message_key = key[:32]

        self.conn[username]['CKr'] = chain_key
        aesgcm = AESGCM(message_key)
        nonce = message[0]['nonce']
        self.conn[username]['Nr'] += 1
        return aesgcm.decrypt(nonce, message[1], None).decode('utf-8')
