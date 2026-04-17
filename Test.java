import java.io.*;
import java.nio.file.*;

public class Test {
    public static void main(String[] args) throws Exception {

        // ─── SHA3 NIST vectors ───────────────────────────────
        byte[] result = SHA3SHAKE.SHA3(256, new byte[0], null);
        System.out.println("SHA3-256 empty input:");
        System.out.println("got:      " + toHex(result));
        System.out.println("expected: a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
        System.out.println(toHex(result).equals(
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a")
            ? "PASS" : "FAIL");
        System.out.println();

        byte[] msg = new byte[200];
        for (int i = 0; i < 200; i++) msg[i] = (byte)0xA3;
        result = SHA3SHAKE.SHA3(256, msg, null);
        System.out.println("SHA3-256 of 0xA3 x200:");
        System.out.println("got:      " + toHex(result));
        System.out.println("expected: 79f38adec5c20307a98ef76e8324afbfd46cfd81b22e3973c65fa1bd9de31787");
        System.out.println(toHex(result).equals(
            "79f38adec5c20307a98ef76e8324afbfd46cfd81b22e3973c65fa1bd9de31787")
            ? "PASS" : "FAIL");
        System.out.println();

        // ─── SHAKE NIST vector ───────────────────────────────
        byte[] shake = SHA3SHAKE.SHAKE(128, new byte[0], 256, null);
        System.out.println("SHAKE-128 empty input:");
        System.out.println("got:      " + toHex(shake));
        System.out.println("expected: 7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26");
        System.out.println(toHex(shake).equals(
            "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26")
            ? "PASS" : "FAIL");
        System.out.println();

        // verify all 4 hash output lengths
         byte[] empty = new byte[0];
        System.out.println("SHA3-224 length: " + SHA3SHAKE.SHA3(224, empty, null).length + " bytes (expected 28) " + (SHA3SHAKE.SHA3(224, empty, null).length == 28 ? "PASS" : "FAIL"));
        System.out.println("SHA3-256 length: " + SHA3SHAKE.SHA3(256, empty, null).length + " bytes (expected 32) " + (SHA3SHAKE.SHA3(256, empty, null).length == 32 ? "PASS" : "FAIL"));
        System.out.println("SHA3-384 length: " + SHA3SHAKE.SHA3(384, empty, null).length + " bytes (expected 48) " + (SHA3SHAKE.SHA3(384, empty, null).length == 48 ? "PASS" : "FAIL"));
        System.out.println("SHA3-512 length: " + SHA3SHAKE.SHA3(512, empty, null).length + " bytes (expected 64) " + (SHA3SHAKE.SHA3(512, empty, null).length == 64 ? "PASS" : "FAIL"));
        
        // ─── output length check ─────────────────────────────
        byte[] t256 = SHA3SHAKE.SHA3(256, new byte[0], null);
        byte[] t512 = SHA3SHAKE.SHA3(512, new byte[0], null);
        System.out.println("SHA3-256 length: " + t256.length + " bytes (expected 32) "
            + (t256.length == 32 ? "PASS" : "FAIL"));
        System.out.println("SHA3-512 length: " + t512.length + " bytes (expected 64) "
            + (t512.length == 64 ? "PASS" : "FAIL"));
        System.out.println();

        // ─── MAC consistency test ────────────────────────────
        // same input + same passphrase must always give same MAC
        byte[] data = "Hello World".getBytes("UTF-8");
        byte[] pass = "mysecret".getBytes("UTF-8");
        SHA3SHAKE s1 = new SHA3SHAKE();
        s1.init(128);
        s1.absorb(pass);
        s1.absorb(data);
        byte[] mac1 = s1.squeeze(32);

        SHA3SHAKE s2 = new SHA3SHAKE();
        s2.init(128);
        s2.absorb(pass);
        s2.absorb(data);
        byte[] mac2 = s2.squeeze(32);

        System.out.println("MAC consistency (same input = same output):");
        System.out.println(toHex(mac1).equals(toHex(mac2)) ? "PASS" : "FAIL");
        System.out.println();

        // ─── encrypt/decrypt round trip ──────────────────────
        // encrypt a known string, decrypt it, check it matches
        byte[] plaintext = "This is a secret message!".getBytes("UTF-8");
        byte[] passphrase = "testpassword".getBytes("UTF-8");

        // encrypt
        byte[] key = SHA3SHAKE.SHAKE(128, passphrase, 128, null);
        byte[] nonce = new byte[16]; // use fixed nonce for testing
        SHA3SHAKE enc = new SHA3SHAKE();
        enc.init(128);
        enc.absorb(nonce);
        enc.absorb(key);
        byte[] keystream = enc.squeeze(plaintext.length);
        byte[] ciphertext = new byte[plaintext.length];
        for (int i = 0; i < plaintext.length; i++)
            ciphertext[i] = (byte)(plaintext[i] ^ keystream[i]);

        // decrypt
        SHA3SHAKE dec = new SHA3SHAKE();
        dec.init(128);
        dec.absorb(nonce);
        dec.absorb(key);
        byte[] keystream2 = dec.squeeze(ciphertext.length);
        byte[] recovered = new byte[ciphertext.length];
        for (int i = 0; i < ciphertext.length; i++)
            recovered[i] = (byte)(ciphertext[i] ^ keystream2[i]);

        String recoveredStr = new String(recovered, "UTF-8");
        System.out.println("Encrypt/decrypt round trip:");
        System.out.println("original:  This is a secret message!");
        System.out.println("recovered: " + recoveredStr);
        System.out.println(recoveredStr.equals("This is a secret message!") ? "PASS" : "FAIL");
    }

    static String toHex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b)
            sb.append(String.format("%02x", x & 0xFF));
        return sb.toString();
    }
}