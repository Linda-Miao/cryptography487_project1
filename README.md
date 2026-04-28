# TCSS 487 Cryptography — Project 1

SHA-3 and SHAKE implementation from scratch in Java, with a CLI application for hashing, MAC generation, and symmetric encryption.

Authors: Rudolf Arakelyan (rudik30) and Linda Miao

## What this implements
- SHA3-224, SHA3-256, SHA3-384, SHA3-512 (FIPS 202)
- SHAKE-128, SHAKE-256 extendable output functions
- Symmetric file encryption using SHAKE-128 as a stream cipher
- SHAKE-128 and SHAKE-256 message authentication codes (MACs)
- All verified against NIST official test vectors

## Attribution
`SHA3SHAKE.java` was written for this project and was structurally inspired by Markku-Juhani Saarinen's tiny_sha3 C implementation:
https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c

## Academic integrity note
This is my own implementation submitted for TCSS 487 at UW Tacoma.
Classmates: do not copy this code for your own submission.

## How to compile
javac SHA3SHAKE.java Main.java Test.java

## Usage
java Main hash <file>
java Main mac <128|256> <file> <passphrase> <outputLengthBytes>
java Main mactext <128|256> "<text>" <passphrase> <outputLengthBytes>
java Main encrypt <inputFile> <passphrase> <outputFile>
java Main decrypt <inputFile> <passphrase> <outputFile>

Backward-compatible forms also work:
- `java Main mac <file> <passphrase> <outputLengthBytes>` (defaults to SHAKE-128)
- `java Main mactext "<text>" <passphrase> <outputLengthBytes>` (defaults to SHAKE-128)
- `java Main encrypt <inputFile> <passphrase>` (defaults output to `<inputFile>.enc`)
- `java Main decrypt <inputFile> <passphrase>` (defaults output to `<inputFile>.dec`)

## Submission note
Submit only the Java source files and `TCSS487_Project1_Report.pdf`. Do not include `.class`, `.jar`, `.exe`, `.enc`, or `.dec` files in the ZIP.
