import os
import pickle
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, BestAvailableEncryption, load_pem_private_key, load_pem_public_key
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHMAC
from cryptography.exceptions import InvalidSignature, InvalidTag

class MessengerServer:
    def __init__(self, server_signing_key, server_decryption_key):
        self.server_signing_key = server_signing_key
        self.server_decryption_key = server_decryption_key

    def decryptReport(self, ct):
        serialized_user_public = ct["user public"]
        loaded_user_public = load_pem_public_key(serialized_user_public)
        nonce = ct["nonce"]
        encrypted = ct["encrypted"]

        shared_key = self.server_decryption_key.exchange(ec.ECDH(), loaded_user_public)   #DHKE

        # CCA-secure El Gamal, hash DH keys to obtain AES key
        hash = hmac.HMAC(serialized_user_public, hashes.SHA256())
        hash.update(shared_key)
        key = hash.finalize()

        aesgcm = AESGCM(key)
        try:
            data = aesgcm.decrypt(nonce, encrypted, None)
        except InvalidTag:
            raise Exception("Invalid Tag while decrypting report!")

        return pickle.loads(data)

    def signCert(self, cert):
        signature = self.server_signing_key.sign(pickle.dumps(cert), ec.ECDSA(hashes.SHA256()))
        return signature

class MessengerClient:

    def __init__(self, name, server_signing_pk, server_encryption_pk):
        self.name = name
        self.server_signing_pk = server_signing_pk
        self.server_encryption_pk = server_encryption_pk
        self.conns = {}
        self.certs = {}

    # generates DH key pair based on eliptic curve P256, returns loaded keys
    def generateDHKeyPair(self):
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()

        return private_key, public_key
    
    # creates + encrypts(using root key) header for sending messages. header is just user's public key
    def createHeader(self, root_key, serialized_public):
        aesgcm = AESGCM(root_key)
        nonce = os.urandom(12)
        header = aesgcm.encrypt(nonce, serialized_public, None)

        return {"nonce": nonce, "public key": header}
    
    # encrypts messages using authenticated AES
    def encrypt(self, aes_key, message):
        aesgcm = AESGCM(aes_key)
        nonce = os.urandom(12)
        encrypted = aesgcm.encrypt(nonce, bytes(message, "ascii"), None)
        
        return {"nonce": nonce, "encrypted": encrypted}

    # decrypts messages/headers using authenticated AES. Returns None if fails, based on requirements
    def decrypt(self, key, cipher, is_header):
        aesgcm = AESGCM(key)
        nonce = cipher["nonce"]

        try:
            if (is_header):
                return aesgcm.decrypt(nonce, cipher["public key"], None)
            return aesgcm.decrypt(nonce, cipher["encrypted"], None)
        except InvalidTag:
            return None
    
    # performs KDF computation for root chain, returns new root key and chain key
    def KDF_rk(self, root_key, DH_out):
        root_out = HKDF(hashes.SHA256(), 64, root_key, None).derive(DH_out)
        root_key = root_out[:32]
        chain_key = root_out[32:]

        return root_key, chain_key

    # performs KDF computation for symmetric-key chain(for sending/receiving), returns new chain key and AES key
    def KDF_ck(self, chain_key):
        sending_out = ConcatKDFHMAC(hashes.SHA256(), 64, None, None).derive(chain_key)
        chain_key = sending_out[:32]
        aes_key = sending_out[32:]

        return chain_key, aes_key

    def generateCertificate(self):
        loaded_private, loaded_public = self.generateDHKeyPair()
        serialized_private = loaded_private.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, BestAvailableEncryption(b"password"))
        serialized_public = loaded_public.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

        self.certs["starting private"] = serialized_private   # store own initial private key, used for comparison later on to determine if user has replied
        certificate = {"name": self.name, "public key": serialized_public}
        return certificate

    def receiveCertificate(self, certificate, signature):
        try:
            self.server_signing_pk.verify(signature, pickle.dumps(certificate), ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            raise Exception("Invalid Signature!")

        peer_name = certificate["name"]
        serialized_peer_public = certificate["public key"]
        self.certs[peer_name] = serialized_peer_public   # store peer intital public key

    def sendMessage(self, name, message):
        if name in self.conns:  # talked before
            if self.certs[name] == self.conns[name]["next public"]:    # other party hasn't replied, dont need do DH ratchet
                chain_key = self.conns[name]["next chain"]
                new_chain_key, aes_key = self.KDF_ck(chain_key)

                # form header and cipher. In this case, root and public key still the same
                root_key = self.conns[name]["next root"]
                serialized_peer_public = self.conns[name]["next public"]
                header = self.createHeader(root_key, serialized_peer_public)
                cipher = self.encrypt(aes_key, message)

                self.conns[name]["next chain"] = new_chain_key  # only need save new chain key. Root, public and private keys still the same

            else:   # other party replied, need to do DH ratchet
                # DH ratchet
                serialized_peer_public = self.conns[name]["next public"]
                loaded_peer_public = load_pem_public_key(serialized_peer_public)

                next_loaded_own_private, next_loaded_own_public = self.generateDHKeyPair()
                next_serialized_own_public = next_loaded_own_public.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
                next_serialized_own_private = next_loaded_own_private.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, BestAvailableEncryption(b"password"))
                DH_out = next_loaded_own_private.exchange(ec.ECDH(), loaded_peer_public)

                # form header and cipher
                new_root_key, chain_key = self.KDF_rk(self.conns[name]["next root"], DH_out)
                new_chain_key, aes_key = self.KDF_ck(chain_key)
                header = self.createHeader(self.conns[name]["next root"], next_serialized_own_public)
                cipher = self.encrypt(aes_key, message)

                # save new root key, new chain key and new own private key. public key still the same
                to_save = {"next root": new_root_key, "next chain": new_chain_key, "next private": next_serialized_own_private, "next public": serialized_peer_public}
                self.conns[name] = to_save

        else:  # new connection, use starting public cert for DHKE
            # DHKE to generate root key
            serialized_peer_public = self.certs[name]
            loaded_peer_public = load_pem_public_key(serialized_peer_public)
            serialized_own_private = self.certs["starting private"]
            loaded_own_private = load_pem_private_key(serialized_own_private, b"password")
            root_key = loaded_own_private.exchange(ec.ECDH(), loaded_peer_public)

            # generate new DH key pair, to be sent over in header
            new_loaded_own_private, new_loaded_own_public = self.generateDHKeyPair()
            new_serialized_own_public = new_loaded_own_public.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
            header = self.createHeader(root_key, new_serialized_own_public)

            # DH and symmetric-key ratchet
            DH_out = new_loaded_own_private.exchange(ec.ECDH(), loaded_peer_public)
            new_root_key, chain_key = self.KDF_rk(root_key, DH_out)
            new_chain_key, aes_key = self.KDF_ck(chain_key)

            cipher = self.encrypt(aes_key, message)

            # save state of keys for future conversations
            new_serialized_own_private = new_loaded_own_private.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, BestAvailableEncryption(b"password"))
            to_save = {"next root": new_root_key, "next chain": new_chain_key, "next private": new_serialized_own_private, "next public": serialized_peer_public}
            self.conns[name] = to_save

        return header, cipher

    def receiveMessage(self, name, header, ciphertext):
        if name in self.conns:   # talked before
            if self.certs["starting private"] == self.conns[name]["next private"]:   # I haven't replied, dont need do DH ratchet
                new_chain_key, aes_key = self.KDF_ck(self.conns[name]["next chain"])
                message = self.decrypt(aes_key, ciphertext, False)
                if (message == None):
                    return None

                self.conns[name]["next chain"] = new_chain_key   # only need save new chain key. Root, public and private keys still the same

            else:   # other party replied, need to do DH ratchet
                # DH ratchet
                serialized_peer_public = self.decrypt(self.conns[name]["next root"], header, True)
                if (serialized_peer_public == None):
                    return None
                loaded_peer_public = load_pem_public_key(serialized_peer_public)
                loaded_own_private = load_pem_private_key(self.conns[name]["next private"], b"password")
                DH_out = loaded_own_private.exchange(ec.ECDH(), loaded_peer_public)

                new_root_key, chain_key = self.KDF_rk(self.conns[name]["next root"], DH_out)
                new_chain_key, aes_key = self.KDF_ck(chain_key)

                message = self.decrypt(aes_key, ciphertext, False)
                if (message == None):
                    return None

                # save new root key, new chain key and new peer public key. own private key still the same
                to_save = {"next root": new_root_key, "next chain": new_chain_key, "next private": self.conns[name]["next private"], "next public": serialized_peer_public}
                self.conns[name] = to_save

        else:   # new conversation
            # DHKE to generate root key
            serialized_peer_public = self.certs[name]
            loaded_peer_public = load_pem_public_key(serialized_peer_public)
            serialized_own_private = self.certs["starting private"]
            loaded_own_private = load_pem_private_key(serialized_own_private, b"password")
            root_key = loaded_own_private.exchange(ec.ECDH(), loaded_peer_public)

            # decrypt header using root key to get public key
            new_serialized_peer_public = self.decrypt(root_key, header, True)
            if (new_serialized_peer_public == None):
                return None
            new_loaded_peer_public = load_pem_public_key(new_serialized_peer_public)

            # DH and symmetric-key ratchet to get AES key for decryption
            DH_out = loaded_own_private.exchange(ec.ECDH(), new_loaded_peer_public)
            new_root_key, chain_key = self.KDF_rk(root_key, DH_out)
            new_chain_key, aes_key = self.KDF_ck(chain_key)

            message = self.decrypt(aes_key, ciphertext, False)
            if (message == None):
                return None

            # save new root key, new chain key and new peer public key. own private key still the same
            to_save = {"next root": new_root_key, "next chain": new_chain_key, "next private": serialized_own_private, "next public": new_serialized_peer_public}
            self.conns[name] = to_save
            
        return message.decode("ascii")

    def report(self, name, message):
        plain = {"name": name, "message": message}   # return plain for main.py to check if cipher got decrypted properly

        # DHKE
        loaded_own_private, loaded_own_public = self.generateDHKeyPair()
        serialized_own_public = loaded_own_public.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        shared_key = loaded_own_private.exchange(ec.ECDH(), self.server_encryption_pk)

        # CCA-secure El Gamal, hash DH keys to obtain AES key
        hash = hmac.HMAC(serialized_own_public, hashes.SHA256())
        hash.update(shared_key)
        key = hash.finalize()

        # encrypt using AES
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        encrypted = aesgcm.encrypt(nonce, pickle.dumps(plain), None)

        cipher = {"user public": serialized_own_public, "nonce": nonce, "encrypted": encrypted}   # return own public key + ciphertext

        return plain, cipher