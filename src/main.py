"""Implementation of the AES-CBC padding oracle attack."""

import argparse
import base64
import logging

from oracle import oracle, encrypt
from settings import BLOCK_SIZE, SAMPLE_TEXT

LOGGER = logging.getLogger(__name__)

def break_ciphertext(ciphertext: bytes, iv: bytes | None = None, native_padder: bool = False) -> bytes:
    """Demonstration of the Padding Oracle Attack."""
    p = bytearray(len(ciphertext))
    blocks = len(ciphertext) // BLOCK_SIZE

    # Go over each block except for the first one. We need the IV, which we don't have
    for i in range(blocks - 1, -1, -1):
        c = ciphertext[i * BLOCK_SIZE:(i+1) * BLOCK_SIZE]                   # Current block
        c_prev = bytearray(ciphertext[(i-1) * BLOCK_SIZE:i * BLOCK_SIZE])   # Previous

        if i == 0:
            if iv:
                c_prev = bytearray(iv)
            else:
                break

        j_start = BLOCK_SIZE - 1
        probe = c_prev[:]
        padding = 0

        # Go over each byte of the block
        for j in range(j_start, -1, -1):
            padding += 1

            # Prepare next round
            for k in range(j_start, j, -1):
                probe[k] = padding ^ c_prev[k] ^ p[i * BLOCK_SIZE + k]

            # Break any native padding so that we don't hit it by mistake
            if j > 0:
                probe[j-1] ^= 1

            for x in range(256):
                probe[j] = x

                if oracle(probe + c, native_padder):
                    p[i * BLOCK_SIZE + j] = c_prev[j] ^ x ^ padding
                    break

    return bytes(p)


# =======  Entrypoint  ====================================================== #

def parse_args() -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(
        prog="PaddingOracleAttack",
        description="Demonstration of the Padding Oracle Attack"
    )

    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "-p", "--plaintext",
        help="Plaintext to encrypt using AES-CBC mode (base64-encoded). Default: sample text."
    )
    group.add_argument(
        "-c", "--ciphertext",
        help="AES-CBC ciphertext to decrypt (base64-encoded). Default: sample text."
    )

    parser.add_argument(
        "-i", "--iv",
        help="Optional IV for decrypting the first block (base64-encoded)."
    )
    parser.add_argument(
        "--use-native-padder",
        action="store_true",
        default=False,
        help="Use cryptography's implementation of the PKCS#7 padder"
    )

    return parser.parse_args()

def main():
    """"Entrypoint."""
    logging.basicConfig(
        level=logging.INFO,
        format="[%(levelname)s] %(message)s"
    )

    args = parse_args()

    iv = base64.b64decode(args.iv) if args.iv else None
    use_native_padder = args.use_native_padder

    if args.plaintext:
        c = encrypt(base64.b64decode(args.plaintext), use_native_padder)
    elif args.ciphertext:
        c = base64.b64decode(args.ciphertext)
    else:
        logging.info("No input provided, using sample text: %s", SAMPLE_TEXT)
        c = encrypt(SAMPLE_TEXT.encode(), use_native_padder)

    logging.info("Ciphertext: %s", c)

    p = break_ciphertext(c, iv, use_native_padder)
    logging.info("Recovered plaintext: %s", p.decode())

if __name__ == "__main__":
    main()
