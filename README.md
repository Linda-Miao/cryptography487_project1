# TCSS 487 Cryptography — Project 1

SHA-3 and SHAKE implementation from scratch in Java, with a CLI application for hashing, MAC generation, and symmetric encryption.

## What this implements
- SHA3-224, SHA3-256, SHA3-384, SHA3-512 (FIPS 202)
- SHAKE-128, SHAKE-256 extendable output functions
- Symmetric file encryption using SHAKE-128 as a stream cipher
- SHAKE-128 message authentication codes (MACs)
- All verified against NIST official test vectors

## Academic integrity note
This is my own implementation submitted for TCSS 487 at UW Tacoma.
Classmates: do not copy this code for your own submission.

## How to compile
javac SHA3SHAKE.java Main.java

## Usage
java Main hash <file>
java Main mac <file> <passphrase> <outputLengthBytes>
java Main mactext "<text>" <passphrase> <outputLengthBytes>
java Main encrypt <file> <passphrase>
java Main decrypt <file.enc> <passphrase>
