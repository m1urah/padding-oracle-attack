"""Simple implementation of the PKCS#7 padding algorithm."""

from typing import Union

BytesLike = Union[bytes, bytearray, memoryview]
BytesTuple = (bytes, bytearray, memoryview)


def pad(data: BytesLike, block_size: int = 16) -> bytes:
    """Apply PKCS#7-compliant padding.
    
    PKCS#7 always add padding: if len(data) is already a multiple of block_size, a full block of
    padding (value == block_size) is appended.

    Args:
        data: Bytes-like object to pad.
        block_size: Block size in bytes. Must be in [1, 255].

    Returns:
        The padded object as bytes.
    """
    if not isinstance(block_size, int):
        raise TypeError("block_size must be of 'int' type.")
    if block_size < 1 or block_size > 255:
        raise ValueError("block_size must be a positive integer between 1 and 255")

    if not isinstance(data, BytesTuple):
        raise TypeError("data must be bytes-like (bytes, bytearray, or memoryview).")

    b = data if isinstance(data, bytes) else bytes(data)

    rem = len(b) % block_size
    pad_len = block_size - rem if rem else block_size

    return b + bytes([pad_len]) * pad_len

def unpad(data: BytesLike, block_size: int = 16) -> bytes:
    """Reverse PKCS#7 padding."""
    if not isinstance(block_size, int):
        raise TypeError("block_size must be of 'int' type.")
    if block_size < 1 or block_size > 255:
        raise ValueError("block_size must be a positive integer between 1 and 255")

    if not isinstance(data, BytesTuple):
        raise TypeError("data must be bytes-like (bytes, bytearray, or memoryview).")

    b = data if isinstance(data, bytes) else bytes(data)

    if not is_pkcs7_padded(b, block_size):
        raise ValueError("data doesn't conform with PKCS#7 padding.")

    pad_len = b[-1]
    return b[:-pad_len]

def is_pkcs7_padded(data: BytesLike, block_size: int = 16) -> bool:
    """
    Returns true if the input's data lenght is a multiple of `block_size` and its trailing bytes
    form a valid PKCS#7 for that block size.

    Args:
        data: The input data.
        block_size: Block size. Defaults to 16 (AES).

    Returns:
        A boolean indicating if `data` is PKCS#7 padded.
    
    Raises:
        TypeError: If an arguments has an incorrect type.
        ValueError: If block_size is outside the valid range [1, 255].
    """
    if not isinstance(data, BytesTuple):
        raise TypeError("data must be of 'bytes' type.")
    if not isinstance(block_size, int):
        raise TypeError("block_size must be of 'int' type.")
    if block_size < 1 or block_size > 255:
        raise ValueError("block_size must be a positive integer between 1 and 255")

    if len(data) % block_size != 0:
        return False

    b = data if isinstance(data, bytes) else bytes(data)

    pad_len = b[-1]
    if pad_len < 1 or pad_len > block_size:
        return False

    # Constant-time-ish check over the padding region to avoid side channel attacks
    bad = 0
    for byte in b[-pad_len:]:
        bad |= (byte ^pad_len)

    return bad == 0
