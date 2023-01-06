#!/usr/bin/env python3

import pickle
import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class MessengerClient:

    def __init__(self, username, ca_pub_key):
        """ Inicijalizacija klijenta

        Argumenti:
        username (str) -- ime klijenta
        ca_pub_key     -- javni ključ od CA (certificate authority)

        """
        self.username = username
        self.ca_pub_key = ca_pub_key
        # Aktivne konekcije s drugim klijentima
        self.conns = {}
        # Inicijalni Diffie-Hellman par ključeva iz metode `generate_certificate`
        self.dh_key_pair = ()
        self.salt = b"\xfd\xa4\xc3\x95\xd6\xaaE\x95\xb473\xc9\xec\x9c]\xb4"

    def generate_certificate(self):
        """ Generira par Diffie-Hellman ključeva i vraća certifikacijski objekt

        Metoda generira inicijalni Diffie-Hellman par kljuceva; serijalizirani
        javni kljuc se zajedno s imenom klijenta postavlja u certifikacijski
        objekt kojeg metoda vraća. Certifikacijski objekt moze biti proizvoljan (npr.
        dict ili tuple). Za serijalizaciju kljuca mozete koristiti
        metodu `public_bytes`; format (PEM ili DER) je proizvoljan.

        Certifikacijski objekt koji metoda vrati bit će potpisan od strane CA te
        će tako dobiveni certifikat biti proslijeđen drugim klijentima.

        """
        self.dh_key_pair = self.generate_dh()

        certificate = {
            'username': self.username,
            'public_key':
                self.dh_key_pair[0].public_bytes(encoding=serialization.Encoding.PEM,
                                                 format=serialization.PublicFormat.SubjectPublicKeyInfo)
        }
        return certificate

    def receive_certificate(self, cert, signature):
        """ Verificira certifikat klijenta i sprema informacije o klijentu (ime
            i javni ključ)

        Argumenti:
        cert      -- certifikacijski objekt
        signature -- digitalni potpis od `cert`

        Metoda prima certifikacijski objekt (koji sadrži inicijalni
        Diffie-Hellman javni ključ i ime klijenta) i njegov potpis kojeg
        verificira koristeći javni ključ od CA i, ako je verifikacija uspješna,
        sprema informacije o klijentu (ime i javni ključ). Javni ključ od CA je
        spremljen prilikom inicijalizacije objekta.

        """
        try:
            self.ca_pub_key.verify(signature, pickle.dumps(cert), ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            print("Invalid signature for certificate")
            return

        conn_public_key = serialization.load_pem_public_key(cert['public_key'],
                                                            backend=default_backend())

        self.conns[cert['username']] = {'DHs': self.dh_key_pair, 'DHr': conn_public_key,
                                        'RK': self.dh(self.dh_key_pair, conn_public_key), 'CKs': None,
                                        'CKr': None}

    def generate_dh(self):
        dh_private_key = X25519PrivateKey.generate()
        return dh_private_key.public_key(), dh_private_key

    def dh(self, dh_key_pair, conn_public_key):
        dh_out = dh_key_pair[1].exchange(conn_public_key)
        return dh_out

    def kdf_rk(self, rk, dh_out):
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32 * 2,
            salt=dh_out,
            info=None,
            backend=default_backend()
        )
        output = hkdf.derive(rk)
        return output[:32], output[32:]

    def kdf_ck(self, ck):
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32 * 2,
            salt=self.salt,
            info=None,
            backend=default_backend()
        )
        output = hkdf.derive(ck)
        return output[:32], output[32:]

    def encrypt(self, mk, plaintext, nonce):
        aesgcm = AESGCM(mk)
        cipher = aesgcm.encrypt(nonce, bytes(plaintext, 'utf-8'), None)
        return cipher

    def decrypt(self, mk, ciphertext, nonce):
        aesgcm = AESGCM(mk)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None).decode('utf-8')
        return plaintext

    def send_message(self, username, message):
        """ Slanje poruke klijentu

        Argumenti:
        message  -- poruka koju ćemo poslati
        username -- klijent kojem šaljemo poruku `message`

        Metoda šalje kriptiranu poruku sa zaglavljem klijentu s imenom `username`.
        Pretpostavite da već posjedujete certifikacijski objekt od klijenta
        (dobiven pomoću `receive_certificate`) i da klijent posjeduje vaš.
        Ako već prije niste komunicirali, uspostavite sesiju tako da generirate
        nužne `double ratchet` ključeve prema specifikaciji.

        Svaki put kada šaljete poruku napravite `ratchet` korak u `sending`
        lanacu (i `root` lanacu ako je potrebno prema specifikaciji).  S novim
        `sending` ključem kriptirajte poruku koristeći simetrični kriptosustav
        AES-GCM tako da zaglavlje poruke bude autentificirano.  Ovo znači da u
        zaglavlju poruke trebate proslijediti odgovarajući inicijalizacijski
        vektor.  Zaglavlje treba sadržavati podatke potrebne klijentu da
        derivira novi ključ i dekriptira poruku.  Svaka poruka mora biti
        kriptirana novim `sending` ključem.

        Metoda treba vratiti kriptiranu poruku zajedno sa zaglavljem.

        """

        # inicijalizacija
        if self.conns[username]['CKs'] is None and self.conns[username]['CKr'] is None:
            new_dh_key = self.generate_dh()
            self.conns[username]['DHs'] = new_dh_key
            rk, cks = self.kdf_rk(self.conns[username]['RK'], self.dh(new_dh_key, self.conns[username]['DHr']))
            self.conns[username]['RK'] = rk
            self.conns[username]['CKs'] = cks

        self.conns[username]['CKs'], mk = self.kdf_ck(self.conns[username]['CKs'])

        nonce = os.urandom(12)
        header = {'DHr': self.conns[username]['DHs'][0], 'IV': nonce}
        cipher = self.encrypt(mk, message, nonce)
        return header, cipher

    def receive_message(self, username, message):
        """ Primanje poruke od korisnika

        Argumenti:
        message  -- poruka koju smo primili
        username -- klijent koji je poslao poruku

        Metoda prima kriptiranu poruku od klijenta s imenom `username`.
        Pretpostavite da već posjedujete certifikacijski objekt od klijenta
        (dobiven pomoću `receive_certificate`) i da je klijent izračunao
        inicijalni `root` ključ uz pomoć javnog Diffie-Hellman ključa iz vašeg
        certifikata.  Ako već prije niste komunicirali, uspostavite sesiju tako
        da generirate nužne `double ratchet` ključeve prema specifikaciji.

        Svaki put kada primite poruku napravite `ratchet` korak u `receiving`
        lanacu (i `root` lanacu ako je potrebno prema specifikaciji) koristeći
        informacije dostupne u zaglavlju i dekriptirajte poruku uz pomoć novog
        `receiving` ključa. Ako detektirate da je integritet poruke narušen,
        zaustavite izvršavanje programa i generirajte iznimku.

        Metoda treba vratiti dekriptiranu poruku.

        """
        header, cipher = message[0], message[1]
        if header['DHr'] != self.conns[username]['DHr']:
            print('pozvan if u receive')
            self.conns[username]['DHr'] = header['DHr']
            self.conns[username]['RK'], self.conns[username]['CKr'] = self.kdf_rk(self.conns[username]['RK'],
                                                                                  self.dh(self.conns[username]['DHs'],
                                                                                          self.conns[username]['DHr']))
            self.conns[username]['DHs'] = self.generate_dh()
            self.conns[username]['RK'], self.conns[username]['CKs'] = self.kdf_rk(self.conns[username]['RK'],
                                                                                  self.dh(self.conns[username]['DHs'],
                                                                                          self.conns[username]['DHr']))

        self.conns[username]['CKr'], mk = self.kdf_ck(self.conns[username]['CKr'])
        nonce = header['IV']
        plaintext = self.decrypt(mk, cipher, nonce)
        return plaintext

def main():
    pass


if __name__ == "__main__":
    main()
