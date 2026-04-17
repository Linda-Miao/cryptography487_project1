public class SHA3SHAKE {

    // -------------------------------------------------------
    // RC — round constants for the iota step
    // 24 constants, one per round. These are fixed values
    // defined by the Keccak spec. They break symmetry in the
    // state so that each round produces a different scramble.
    // Without them, all 24 rounds would do the same thing.
    // -------------------------------------------------------
    private static final long[] RC = {
        0x0000000000000001L, 0x0000000000008082L,
        0x800000000000808AL, 0x8000000080008000L,
        0x000000000000808BL, 0x0000000080000001L,
        0x8000000080008081L, 0x8000000000008009L,
        0x000000000000008AL, 0x0000000000000088L,
        0x0000000080008009L, 0x000000008000000AL,
        0x000000008000808BL, 0x800000000000008BL,
        0x8000000000008089L, 0x8000000000008003L,
        0x8000000000008002L, 0x8000000000000080L,
        0x000000000000800AL, 0x800000008000000AL,
        0x8000000080008081L, 0x8000000000008080L,
        0x0000000080000001L, 0x8000000080008008L
    };

    // -------------------------------------------------------
    // RHO — rotation offsets for the rho step
    // each lane gets rotated left by a different amount.
    // this spreads bits across the 64-bit width of each lane.
    // index matches lane index in the 5x5 grid (lane[i] rotates
    // by RHO[i] bits).
    // -------------------------------------------------------
    private static final int[] RHO = {
         0,  1, 62, 28, 27,
        36, 44,  6, 55, 20,
         3, 10, 43, 25, 39,
        41, 45, 15, 21,  8,
        18,  2, 61, 56, 14
    };

    // -------------------------------------------------------
    // Fields — the sponge's internal memory
    // -------------------------------------------------------
    private long[] state;    // the 1600-bit state as 25 longs (5x5 grid)
    private int bufLen;      // how many bytes we have absorbed into the
                             // current block so far (0 to rate-1)
    private int rate;        // rate in bytes — how many bytes per block
                             // (depends on security level)
    private int suffix;      // the suffix number passed to init()
                             // e.g. 256 for SHA3-256 or SHAKE-256
    private boolean squeezing; // false = absorbing, true = squeezing
                               // once true, no more absorb() calls allowed
    private byte domainByte; // 0x06 for SHA-3, 0x1F for SHAKE
                             // tells Keccak which function family this is
                             // (domain separation)

    // -------------------------------------------------------
    // Constructor — nothing to do, init() sets everything up
    // -------------------------------------------------------
    public SHA3SHAKE() {}

    // -------------------------------------------------------
    // init() — reset the sponge for a new hash
    // must be called before absorb() or squeeze()
    // -------------------------------------------------------
    public void init(int suffix) {
        state = new long[25];  // fresh state — all 1600 bits = zero
        switch (suffix) {
            // rate = (1600 - 2*security) / 8 bytes
            // higher security = smaller rate = slower but safer
            case 128: rate = 168; domainByte = 0x1F; break; // SHAKE-128
            case 256: rate = 136; domainByte = 0x1F; break; // SHAKE-256
            case 224: rate = 144; domainByte = 0x06; break; // SHA3-224
            case 384: rate = 104; domainByte = 0x06; break; // SHA3-384
            case 512: rate =  72; domainByte = 0x06; break; // SHA3-512
            default: throw new IllegalArgumentException(
                "suffix must be 128, 224, 256, 384 or 512");
        }
        this.suffix = suffix;
        bufLen = 0;       // no bytes absorbed yet
        squeezing = false; // we are in absorb phase
    }

    // initSHA3 — used by the static SHA3() method
    // forces domainByte = 0x06 regardless of suffix number
    // needed because SHA3-256 and SHAKE-256 both use suffix 256
    // but need different domain bytes
    private void initSHA3(int suffix) {
        init(suffix);
        domainByte = 0x06; // SHA-3 domain byte — overrides init()
    }

    // initSHAKE — used by the static SHAKE() method
    // forces domainByte = 0x1F regardless of suffix number
    private void initSHAKE(int suffix) {
        init(suffix);
        domainByte = 0x1F; // SHAKE domain byte — overrides init()
    }

    // -------------------------------------------------------
    // absorb() — feed message bytes into the sponge
    // -------------------------------------------------------
    public void absorb(byte[] data, int pos, int len) {
        if (squeezing)
            throw new IllegalStateException("cannot absorb after squeezing");

        for (int i = pos; i < pos + len; i++) {

            // XOR one byte directly into the state at position bufLen
            // bufLen/8  = which lane (0-24)
            // bufLen%8  = which byte slot inside that lane (0-7)
            // << shift  = move the byte into the correct bit position
            // & 0xFF    = treat Java's signed byte as unsigned
            state[bufLen / 8] ^= (long)(data[i] & 0xFF) << (8 * (bufLen % 8));

            bufLen++; // move to next byte position

            if (bufLen == rate) {
                // we have filled one complete rate-sized block
                // scramble the state before accepting more input
                keccakF();
                bufLen = 0; // reset — ready for next block
            }
        }
    }

    // convenience overloads — simpler ways to call absorb()
    public void absorb(byte[] data, int len) { absorb(data, 0, len); }
    public void absorb(byte[] data) { absorb(data, 0, data.length); }

    // -------------------------------------------------------
    // squeeze() — read output bytes from the sponge
    // -------------------------------------------------------
    public byte[] squeeze(byte[] out, int len) {
        if (!squeezing) {
            // first squeeze call — must finalize input with padding first

            // XOR the domain byte at the current position
            // this marks the end of the message and identifies
            // the function (SHA-3 vs SHAKE) — domain separation
            state[bufLen / 8] ^= (long)(domainByte & 0xFF) << (8 * (bufLen % 8));

            // XOR 0x80 into the very last byte of the rate block
            // this is the pad10*1 rule — sets the final bit to 1
            // together with the domain byte, this uniquely frames
            // every message so no two different messages can
            // produce the same padded block
            state[(rate - 1) / 8] ^= 0x80L << (8 * ((rate - 1) % 8));

            keccakF();       // scramble after padding
            squeezing = true; // switch to squeeze phase
            bufLen = 0;      // start reading from byte 0 of the state
        }

        for (int i = 0; i < len; i++) {
            if (bufLen == rate) {
                // we have read all rate bytes from the current state
                // scramble again to produce the next block of output
                keccakF();
                bufLen = 0;
            }

            // read one byte from the state at position bufLen
            // same addressing as absorb — lane then byte slot
            // >>> shifts the target byte down to the lowest 8 bits
            // (byte) truncates — keeps only those 8 bits
            out[i] = (byte)(state[bufLen / 8] >>> (8 * (bufLen % 8)));

            bufLen++; // move to next byte position
        }
        return out;
    }

    // convenience overload — allocates output buffer for caller
    public byte[] squeeze(int len) { return squeeze(new byte[len], len); }

    // -------------------------------------------------------
    // digest() — squeeze a fixed-length SHA-3 hash
    // -------------------------------------------------------
    public byte[] digest(byte[] out) {
        squeeze(out, out.length); // squeeze exactly out.length bytes
        return out;
    }

    public byte[] digest() {
        // suffix/8 = output size in bytes
        // e.g. SHA3-256 → 256/8 = 32 bytes
        return digest(new byte[suffix / 8]);
    }

    // -------------------------------------------------------
    // SHA3() — static shortcut for one-shot SHA-3 hashing
    // -------------------------------------------------------
    public static byte[] SHA3(int suffix, byte[] X, byte[] out) {
        if (out == null) out = new byte[suffix / 8]; // allocate if needed
        SHA3SHAKE s = new SHA3SHAKE();
        s.initSHA3(suffix); // use SHA-3 domain byte (0x06)
        s.absorb(X);        // feed entire input
        return s.digest(out); // finalize and return hash
    }

    // -------------------------------------------------------
    // SHAKE() — static shortcut for one-shot SHAKE hashing
    // -------------------------------------------------------
    public static byte[] SHAKE(int suffix, byte[] X, int L, byte[] out) {
        if (out == null) out = new byte[L / 8]; // L is in bits
        SHA3SHAKE s = new SHA3SHAKE();
        s.initSHAKE(suffix); // use SHAKE domain byte (0x1F)
        s.absorb(X);         // feed entire input
        return s.squeeze(out, L / 8); // squeeze L/8 bytes of output
    }

    // -------------------------------------------------------
    // keccakF() — the 24-round permutation (the blend button)
    // scrambles all 25 lanes of the state completely
    // -------------------------------------------------------
    private void keccakF() {
        long[] A = state;      // work directly on the state
        long[] B = new long[25]; // temp storage for pi step
        long[] C = new long[5];  // column XORs for theta
        long[] D = new long[5];  // mixed columns for theta

        for (int round = 0; round < 24; round++) {

            // θ (theta) step 1 — XOR all 5 rows of each column together
            // C[x] = XOR of every lane in column x
            for (int x = 0; x < 5; x++)
                C[x] = A[x] ^ A[x+5] ^ A[x+10] ^ A[x+15] ^ A[x+20];

            // θ (theta) step 2 — mix neighbouring columns
            // D[x] = column to the left XOR (column to the right rotated 1)
            for (int x = 0; x < 5; x++)
                D[x] = C[(x+4)%5] ^ rotL(C[(x+1)%5], 1);

            // θ (theta) step 3 — XOR the mix into every lane
            // every lane gets influence from its neighbouring columns
            for (int x = 0; x < 5; x++)
                for (int y = 0; y < 5; y++)
                    A[x + 5*y] ^= D[x];

            // ρ (rho) + π (pi) combined
            // rho: rotate each lane left by its RHO offset
            // pi: move each lane to a new position in the grid
            // doing both together saves a temporary array
            for (int x = 0; x < 5; x++)
                for (int y = 0; y < 5; y++) {
                    int src = x + 5*y;           // source lane index
                    // pi destination: (x,y) -> (y, 2x+3y mod 5)
                    B[y + 5*((2*x + 3*y) % 5)] = rotL(A[src], RHO[src]);
                }

            // χ (chi) — only non-linear step
            // mixes lanes within each row using AND and NOT
            // this is what makes Keccak cryptographically strong
            for (int x = 0; x < 5; x++)
                for (int y = 0; y < 5; y++)
                    A[x + 5*y] = B[x + 5*y]
                        ^ (~B[(x+1)%5 + 5*y] & B[(x+2)%5 + 5*y]);

            // ι (iota) — XOR round constant into lane[0] only
            // breaks the symmetry between rounds so each round
            // is unique — prevents slide attacks
            A[0] ^= RC[round];
        }
    }

    // -------------------------------------------------------
    // rotL() — rotate a 64-bit value left by n bits
    // bits that fall off the left end wrap around to the right
    // used by rho step to spread bits across the lane width
    // -------------------------------------------------------
    private static long rotL(long x, int n) {
        return (x << n) | (x >>> (64 - n));
    }
}