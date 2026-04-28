/*
 * TCSS 487 Cryptography Project 1
 * Authors: Rudolf Arakelyan (rudik30) and Linda Miao
 */

import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;

public class Main {
    private static final int NONCE_LEN = 16;
    private static final int MAC_LEN = 32;
    private static final SecureRandom RNG = new SecureRandom();

    public static void main(String[] args) {
        if (args.length < 1) {
            printUsage();
            return;
        }

        try {
            switch (args[0]) {
                case "hash":
                    hash(args);
                    break;
                case "mac":
                    mac(args);
                    break;
                case "mactext":
                    mactext(args);
                    break;
                case "encrypt":
                    encrypt(args);
                    break;
                case "decrypt":
                    decrypt(args);
                    break;
                default:
                    System.out.println("Unknown command: " + args[0]);
                    printUsage();
            }
        } catch (Exception ex) {
            System.out.println("Error: " + ex.getMessage());
        }
    }

    static void printUsage() {
        System.out.println("Usage:");
        System.out.println("  java Main hash <file>");
        System.out.println("  java Main mac <128|256> <file> <passphrase> <outputLengthBytes>");
        System.out.println("  java Main mac <file> <passphrase> <outputLengthBytes>  # defaults to SHAKE-128");
        System.out.println("  java Main mactext <128|256> <text> <passphrase> <outputLengthBytes>");
        System.out.println("  java Main mactext <text> <passphrase> <outputLengthBytes>  # defaults to SHAKE-128");
        System.out.println("  java Main encrypt <inputFile> <passphrase> <outputFile>");
        System.out.println("  java Main encrypt <inputFile> <passphrase>  # output defaults to <inputFile>.enc");
        System.out.println("  java Main decrypt <inputFile> <passphrase> <outputFile>");
        System.out.println("  java Main decrypt <inputFile> <passphrase>  # output defaults to <inputFile>.dec");
    }

    static void hash(String[] args) throws Exception {
        if (args.length != 2) {
            System.out.println("Usage: java Main hash <file>");
            return;
        }

        byte[] data = Files.readAllBytes(Paths.get(args[1]));
        byte[] h224 = SHA3SHAKE.SHA3(224, data, null);
        byte[] h256 = SHA3SHAKE.SHA3(256, data, null);
        byte[] h384 = SHA3SHAKE.SHA3(384, data, null);
        byte[] h512 = SHA3SHAKE.SHA3(512, data, null);

        System.out.println("SHA3-224: " + toHex(h224));
        System.out.println("SHA3-256: " + toHex(h256));
        System.out.println("SHA3-384: " + toHex(h384));
        System.out.println("SHA3-512: " + toHex(h512));
    }

    static void mac(String[] args) throws Exception {
        int shakeLevel;
        String fileArg;
        String passphraseArg;
        String outLenArg;

        if (args.length == 5) {
            shakeLevel = parseShakeLevel(args[1]);
            fileArg = args[2];
            passphraseArg = args[3];
            outLenArg = args[4];
        } else if (args.length == 4) {
            shakeLevel = 128;
            fileArg = args[1];
            passphraseArg = args[2];
            outLenArg = args[3];
        } else {
            System.out.println("Usage: java Main mac <128|256> <file> <passphrase> <outputLengthBytes>");
            return;
        }

        byte[] data = Files.readAllBytes(Paths.get(fileArg));
        byte[] passphrase = passphraseArg.getBytes(StandardCharsets.UTF_8);
        int outLen = parseOutputLength(outLenArg);

        SHA3SHAKE sponge = new SHA3SHAKE();
        sponge.init(shakeLevel);
        sponge.absorb(passphrase);
        sponge.absorb(data);
        byte[] tag = sponge.squeeze(outLen);

        System.out.println("SHAKE-" + shakeLevel + " MAC (" + outLen + " bytes): " + toHex(tag));
    }

    static void mactext(String[] args) {
        int shakeLevel;
        String textArg;
        String passphraseArg;
        String outLenArg;

        if (args.length == 5) {
            shakeLevel = parseShakeLevel(args[1]);
            textArg = args[2];
            passphraseArg = args[3];
            outLenArg = args[4];
        } else if (args.length == 4) {
            shakeLevel = 128;
            textArg = args[1];
            passphraseArg = args[2];
            outLenArg = args[3];
        } else {
            System.out.println("Usage: java Main mactext <128|256> <text> <passphrase> <outputLengthBytes>");
            return;
        }

        byte[] data = textArg.getBytes(StandardCharsets.UTF_8);
        byte[] passphrase = passphraseArg.getBytes(StandardCharsets.UTF_8);
        int outLen = parseOutputLength(outLenArg);

        SHA3SHAKE sponge = new SHA3SHAKE();
        sponge.init(shakeLevel);
        sponge.absorb(passphrase);
        sponge.absorb(data);
        byte[] tag = sponge.squeeze(outLen);

        System.out.println("SHAKE-" + shakeLevel + " text MAC (" + outLen + " bytes): " + toHex(tag));
    }

    static void encrypt(String[] args) throws Exception {
        if (args.length != 3 && args.length != 4) {
            System.out.println("Usage: java Main encrypt <inputFile> <passphrase> <outputFile>");
            return;
        }

        byte[] data = Files.readAllBytes(Paths.get(args[1]));
        byte[] passphrase = args[2].getBytes(StandardCharsets.UTF_8);
        String outFile = (args.length == 4) ? args[3] : args[1] + ".enc";

        byte[] key = SHA3SHAKE.SHAKE(128, passphrase, 128, null);
        byte[] nonce = new byte[NONCE_LEN];
        RNG.nextBytes(nonce);

        SHA3SHAKE stream = new SHA3SHAKE();
        stream.init(128);
        stream.absorb(nonce);
        stream.absorb(key);
        byte[] keystream = stream.squeeze(data.length);

        byte[] ciphertext = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            ciphertext[i] = (byte) (data[i] ^ keystream[i]);
        }

        SHA3SHAKE macSponge = new SHA3SHAKE();
        macSponge.init(256);
        macSponge.absorb(key);
        macSponge.absorb(ciphertext);
        byte[] mac = macSponge.digest();

        try (FileOutputStream fos = new FileOutputStream(outFile)) {
            fos.write(nonce);
            fos.write(ciphertext);
            fos.write(mac);
        }

        System.out.println("Encrypted to: " + outFile);
        System.out.println("Nonce: " + toHex(nonce));
        System.out.println("MAC: " + toHex(mac));
    }

    static void decrypt(String[] args) throws Exception {
        if (args.length != 3 && args.length != 4) {
            System.out.println("Usage: java Main decrypt <inputFile> <passphrase> <outputFile>");
            return;
        }

        byte[] fileData = Files.readAllBytes(Paths.get(args[1]));
        if (fileData.length < NONCE_LEN + MAC_LEN) {
            throw new IllegalArgumentException("ciphertext is too short to contain nonce and MAC");
        }

        byte[] passphrase = args[2].getBytes(StandardCharsets.UTF_8);
        String outFile;
        if (args.length == 4) {
            outFile = args[3];
        } else if (args[1].endsWith(".enc")) {
            outFile = args[1].substring(0, args[1].length() - 4) + ".dec";
        } else {
            outFile = args[1] + ".dec";
        }

        byte[] nonce = new byte[NONCE_LEN];
        System.arraycopy(fileData, 0, nonce, 0, NONCE_LEN);

        byte[] storedMac = new byte[MAC_LEN];
        System.arraycopy(fileData, fileData.length - MAC_LEN, storedMac, 0, MAC_LEN);

        byte[] ciphertext = new byte[fileData.length - NONCE_LEN - MAC_LEN];
        System.arraycopy(fileData, NONCE_LEN, ciphertext, 0, ciphertext.length);

        byte[] key = SHA3SHAKE.SHAKE(128, passphrase, 128, null);

        SHA3SHAKE macSponge = new SHA3SHAKE();
        macSponge.init(256);
        macSponge.absorb(key);
        macSponge.absorb(ciphertext);
        byte[] computedMac = macSponge.digest();

        if (!constantTimeEquals(storedMac, computedMac)) {
            System.out.println("MAC verification failed. File may have been tampered with.");
            return;
        }
        System.out.println("MAC verified.");

        SHA3SHAKE stream = new SHA3SHAKE();
        stream.init(128);
        stream.absorb(nonce);
        stream.absorb(key);
        byte[] keystream = stream.squeeze(ciphertext.length);

        byte[] plaintext = new byte[ciphertext.length];
        for (int i = 0; i < ciphertext.length; i++) {
            plaintext[i] = (byte) (ciphertext[i] ^ keystream[i]);
        }

        Files.write(Paths.get(outFile), plaintext);
        System.out.println("Decrypted to: " + outFile);
    }

    static int parseShakeLevel(String arg) {
        int level = Integer.parseInt(arg);
        if (level != 128 && level != 256) {
            throw new IllegalArgumentException("SHAKE level must be 128 or 256");
        }
        return level;
    }

    static int parseOutputLength(String arg) {
        int outLen = Integer.parseInt(arg);
        if (outLen < 1) {
            throw new IllegalArgumentException("outputLengthBytes must be >= 1");
        }
        return outLen;
    }

    static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a == null || b == null) {
            return false;
        }

        int diff = a.length ^ b.length;
        int maxLen = Math.max(a.length, b.length);
        for (int i = 0; i < maxLen; i++) {
            byte ai = (i < a.length) ? a[i] : 0;
            byte bi = (i < b.length) ? b[i] : 0;
            diff |= ai ^ bi;
        }
        return diff == 0;
    }

    static String toHex(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (byte b : data) {
            sb.append(String.format("%02x", b & 0xFF));
        }
        return sb.toString();
    }
}
