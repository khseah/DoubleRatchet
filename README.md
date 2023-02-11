# DoubleRatchet

This is an implementation of a secure and efficient end-to-end encrypted chat client using the **Double Ratchet** algorithm, done as an assignment for UNC COMP590 in 
Fall 2022.

Signal's [published specification](https://signal.org/docs/specifications/doubleratchet/) was used as a reference guide, specifically sections 1, 2 and 3. My
implementation follows the specifications described in section 3. In addition, the chat client also includes a "message reporting" feature, so that a moderator working
for the platform can review abusive messages. The Double Ratchet provides **forward secrecy** and **break-in recovery**.

- `HKDF` with `SHA-256` to ratchet the Diffie-Hellman keys
- `HMAC` with `SHA-256` to implement the symmetric key ratchet
- `AES-GCM` as the symmetric authenticated encryption algorithm
- `P-256` as the eliptic curve for all public key operations
- AD byte sequence input for *ratchetEncrypt* and *ratchetDecrypt* functions are disregarded
- Dropped or out-of-order messages are not handled (section 2.6 is ignored)

Further specifications
- Every client creates an initial DH key pair, which will be used to derive root keys for new communication sessions
- Public keys are distributed through simple certificates. Each client generates his own certificate upon initialization which includes its public key.

The API supports:
- **Client.generateCertificate()**
  - Initialize messenging client for communication with other clients by generating a DH key pair for key exchanges
  - The certificate contains the name of the user and their public key
- **Client.receiveCertificate(certificate, signature)**
  - Takes a certificate from another client, verifies it using its signature, and stores it
  - The client can now send/receive messages from the owner of that certificate
- **Client.sendMessage(name, message)**
  - Sends an encrypted message to a user specified by their name
  - If they have not previously communicated, this method sets up the session by generating the necessary double ratchet keys according to the Signal specs
- **Client.receiveMessage(name, header, ciphertext)**
  - Receives an encrypted message from a user specified by their name
  - If they have not previously communicated, this method sets up the session by generating the necessary double ratchet keys according to the Signal specs
  - If tampering of message is detected, this method returns *None*
- **Client.report(name, message)
  - Creates an abuse report with the provided name and message
  - CCA-secure El-Gamal encryption scheme is used to encrypt the report
- **Server.signCertificate(certificate)**
  - Signs the provided certificate with the server's signing key
  - ECDSA signature using SHA-256 as the hash is used
- **Server.decryptReport(ct)**
  - Decrypts an encrypted abuse report using the server's private decryption key
