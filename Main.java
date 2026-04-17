import java.io.*;
import java.nio.file.*;
import java.security.SecureRandom; // cryptographically strong random numbers (for nonce)

public class Main {
    public static void main(String[] args) throws Exception{
        if (args.length < 1){
            printUsage(); // show them how to use the app
            return; // stop here
        }
        switch (args[0]){
            case "hash":   hash(args);     break; // service 1
            case "mac":    mac(args);      break; // service 2
            case "encrypt": encrypt(args); break;
            case "decrypt": decrypt(args); break;
            case "mactext": mactext(args); break; // bonus service
            default:
                System.out.println("Unknow command: " + args[0]);
                printUsage();
        }

    }

    static void mactext(String[] args) throws Exception {
        // check the user gave us all 3 arguments
        if (args.length < 4){
            System.out.println("Uasage: java Main mactext <text>  <passphrase> <outputLength>");
            return;
        }
        
        // get the text directly from args - no file need 
        // user types the message right on the command line
        byte[] data = args[1].getBytes("UTF-8");

        // get passphrase as bytes
        byte[] passphrase = args[2].getBytes("UTF-8");

        //get desired output length in bytes
        int outLen = Integer.parseInt(args[3]);
        
        // exatctly the same MAC logic as mac() - only the data source charged
        SHA3SHAKE sponge = new SHA3SHAKE();
        sponge.init(128); // absorb passphrase first
        sponge.absorb(data); // then the text input diretly
        byte[] mac = sponge.squeeze(outLen);

        System.out.println("SHAKE-128 MAC of text (" + outLen + " bytes): " + toHex(mac));
    }
    static void printUsage() {
        System.out.println("Usage:");
        System.out.println("   java Main hash<file>");
        System.out.println("   java Main mac<file> <passphrase> <outputLength>");
        System.out.println("   java Main encrypt <file> <passphrase>");
        System.out.println("   java Main decrypt <file> <passphrase>");
    }

    // hash - service 1 (required + bonus)
    // reads a file and prints SHA3-224, SHA3-256, SHA3-384, SHA3-512 hashes
    // arg[0] = "hash"
    // arg[1] = path to the file to hash
    // this is for bonus section that replace above section (hash - service 1;
    static void hash(String[] args) throws Exception{
        // check the user gave us a filename 
        if (args.length < 2){
            System.out.println("Usage: java Main hash <file>");
            return;
        }
        // read he entire file into a byte array
        byte[] data = Files.readAllBytes(Paths.get(args[1]));

        // required: SHA3-256 and SHA3-512

        // SHA3-256 and SHA3-512 bits = 32 bytes output 
        // most common hash size, used for general integrity checking
        byte[] h256 = SHA3SHAKE.SHA3(256, data, null);

        // SHA3-512 - 512 bits = 64 bytes output
        // stronger version, used when extra security margin is needed
        byte[] h512 = SHA3SHAKE.SHA3(512, data, null);

        // bonus: SHA3- 224 and SHA3-384
        // smallest SHA3 variant, compatible with SHA-2 224-bit output
        byte[] h224 = SHA3SHAKE.SHA3(224, data, null);

        //SHA3-384 - 384 bits = 48 bytes output
        // middle ground between 256 and 512 bit security
        byte[] h384 = SHA3SHAKE.SHA3(384, data, null);

        // print all four results in order of size
        System.out.println("SHA3-224: " + toHex(h224));
        System.out.println("SHA3-256: " + toHex(h256));
        System.out.println("SHA3-384: " + toHex(h384));
        System.out.println("SHA3-512: " + toHex(h512));
    }



    // mac - service 2
    // computes a SHAK-bases authentication tag(MAC); arg[0] = "mac; arg[1] = path to the file
    // arg[2] = passphrase(the secret key); arg[3] = desired output length in bytes
    static void mac(String[] args) throws Exception {
        // check the user gave us all 3 arguments
        if(args.length < 4){
            System.out.print("Useage: java Main max <file> <passphrase> <outputlength>");
            return;
        }

        byte[] data = Files.readAllBytes(Paths.get(args[1])); // read the file

        byte[] passphrase = args[2].getBytes("UTF-8"); // get passphrase as bytes
        int outLen = Integer.parseInt(args[3]); // get desired output length in bytes

        SHA3SHAKE sponge = new SHA3SHAKE(); // create a SHAKE-128 sponge
        sponge.init(128);

        // absorb passphrase first, then the data
        // order matters - passphrase acts the secret key
        sponge.absorb(passphrase);
        sponge.absorb(data);

        byte[] mac = sponge.squeeze(outLen); // squeeze out the requested number of bytes

        System.out.println("SHAKE-128 MAC (" + outLen + " bytes):  " + toHex(mac));
    }

    // encrypt — service 3 (required + bonus)
    // encrypts a file using SHAKE-128 as a stream cipher
    // stores nonce + ciphertext + SHA3-256 MAC tag in output file
    // args[0] = "encrypt"
    // args[1] = path to the file to encrypt
    // args[2] = passphrase

    static void encrypt(String[] args) throws Exception{
        // check the user gave us file and passphrase
        if(args.length < 3){
            System.out.println("Usage: java Main encrypt <file> <passphrase>");
            return;
        }
        // read the file to encrypt 
        byte[] data = Files.readAllBytes(Paths.get(args[1]));
        // get passphrase as bytes
        byte[] passphrase = args[2].getBytes("UTF-8");

        // step 1 - hash the passphrase to get a 128 -bit (16 byte) symmetric key
        byte[] key = SHA3SHAKE.SHAKE(128, passphrase, 128, null);
        // step 2 - generate a random 128-bit (16 byte) nonce
        // nonce = number used once - makes every encryption unique
        // even if you encrypt the same file twince with the same password
        // the once encures the ciphertext is different each time
        byte[] nonce = new byte[16];
        new SecureRandom().nextBytes(nonce);

        // step 3 - create keysstream by absorbing nonce then key 
        SHA3SHAKE sponge = new SHA3SHAKE();
        sponge.init(128);
        sponge.absorb(nonce); // absorb once first
        sponge.absorb(key); // then the key
        byte[] keystream = sponge.squeeze(data.length); 
        // step 4 - XOR plaintext with keystream to get ciphertext
        byte[] ciphertext = new byte[data.length];
        for (int i = 0; i < data.length; i++)
            ciphertext[i] = (byte)(data[i] ^ keystream[i]);

        // Step 5 - bonus: compute MAC tag over the ciphertext
        // we MAC the ciphertext (not plaintext) so we can verify
        // integrity before decryption - encrypt-then-MAC pattern
        // used SHA3-256 with the same key as encryption
        SHA3SHAKE macSponge = new SHA3SHAKE();
        macSponge.init(256); // SHA3-256 for the MAC 
        macSponge.absorb(key); //absorb the key first
        macSponge.absorb(ciphertext); // then the ciphertext
        byte[] mac = macSponge.digest(); // get the 32-byte MAC tag

        // Step 6 - write nonce + ciphtext + MAC to output file
        // layout: [16 bytes nonce ][ ciphertext ][ 32 bytes MAC]
        String outFile = args[1] + ".enc";
        try (FileOutputStream fos = new FileOutputStream(outFile)) {
            fos.write(nonce); // first 16 bytes = nounce
            fos.write(ciphertext); // middle = ciphertext
            fos.write(mac); // last 32 byes = MAC tag
        }

        System.out.println("Encrypted to: " + outFile);
        System.out.println("Nonce: " + toHex(nonce));
        System.out.println("Mac: " + toHex(mac));
    }

    // decrypt - service 4 (required + bonus)
    // decrypts a file and verifies the MAC tag
    // args[0] = "decrypt"
    // args[1] = path to the encrypted file
    // args[2] = passphrase
 

    static void decrypt(String[] args) throws Exception{
        // check the user gave us file and passphrase
        if (args.length < 3){
            System.out.println("Usage: java Main decrypt <file> <passphrase>");
            return;
        }
        // read the encrypted file (nonce + ciphtext)
        byte[] fileData = Files.readAllBytes(Paths.get(args[1]));
        // get passphrase as bytes
        byte[] passphrase = args[2].getBytes("UTF-8");
        // step 1 - extract the nonce from the first 16 bytes
        byte[] nonce = new byte[16];
        System.arraycopy(fileData, 0, nonce, 0, 16);

        // step 2 = extract MAC from last 32 bytes
        // bonus: MAC tag is stored at the end of the file
        byte[] storedMac = new byte[32];
        System.arraycopy(fileData, fileData.length - 32, storedMac, 0, 32);

        // step 3 - extract ciphertext (everthing between nonce and MAC)
        // File layout:[ 16 nonce ][ ciphtext ][ 32 MAC ]
        byte[] ciphertext = new byte[fileData.length - 16 - 32];
        System.arraycopy(fileData, 16, ciphertext, 0, ciphertext.length); 

        // Step 4 - recreate the same key from passphrase
        byte[] key = SHA3SHAKE.SHAKE(128, passphrase, 128, null);


        // step 5 - bonus: verify MAC before decrepting
        // recomupte MAC from ciphertext using same key
        // if MAC doen't match, file was tampered with - reject it 
        SHA3SHAKE sponge = new SHA3SHAKE();
        sponge.init(256);
        sponge.absorb(key); // same key from passp
        sponge.absorb(ciphertext); 
        byte[] computedMac = sponge.digest();

        // compare stored MAC vs computed MAC byte by byte
        boolean macOk = java.util.Arrays.equals(storedMac, computedMac);
        if (!macOk) {
            System.out.println("MAC FAILED - file may have been tampered with!");
            return; // stop - do not decrypt a tampered file 
        }
        System.out.println("MAC verified — file is authentic.");

        // step 6 - recreate the same keystream (nonce then key)
        SHA3SHAKE disSponge = new SHA3SHAKE();
        sponge.init(128);
        sponge.absorb(nonce);
        sponge.absorb(key);
        byte[] keystream = sponge.squeeze(ciphertext.length);

        // Step 7 - XOR ciphertext with keystream to recover plaintext
        // XOR is its own inverse: ciphertext XOR keystream = plaintext
        byte[] plaintext = new byte[ciphertext.length];
        for (int i = 0; i < ciphertext.length; i++){
            plaintext[i] = (byte)(ciphertext[i] ^ keystream[i]);
        }

        // step 8 - write plaintext to output file
        String outFile = args[1].replace(".enc", ".dec");
        Files.write(Paths.get(outFile), plaintext);
        for (int i = 0; i < ciphertext.length; i++)
            plaintext[i] = (byte)(ciphertext[i] ^ keystream[i]);
           System.out.println("Decrypted to: " + outFile);
    }

    // toHex - helper used by all services for printing output
    // converts a byte array to a readable hex string. for instance [0x4A, 0xFF] -> "4aff"
    static String toHex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for(byte x : b)
            sb.append(String.format("%02x", x & 0xFF));
        return sb.toString();
    }

}
