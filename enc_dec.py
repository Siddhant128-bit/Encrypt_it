import os
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend

CHUNK_SIZE = 64 * 1024  # 64 KB
SALT_SIZE = 16
NONCE_SIZE = 12  # recommended for GCM
TAG_SIZE = 16
MAGIC = b'PYENC1'  # file magic + version

def generate_password(num_bytes: int = 32) -> str:
    """Generate a URL-safe password string (you can store or send this to user)."""
    return secrets.token_urlsafe(num_bytes)  # returns a longer string

def derive_key_from_password(password: str, salt: bytes, length: int = 32) -> bytes:
    """Derive a symmetric key from password using scrypt KDF."""
    password_bytes = password.encode('utf-8')
    kdf = Scrypt(salt=salt, length=length, n=2**14, r=8, p=1, backend=default_backend())
    return kdf.derive(password_bytes)

def encrypt_file(in_path: str, out_path: str, password: str):
    salt = secrets.token_bytes(SALT_SIZE)
    key = derive_key_from_password(password, salt, length=32)

    nonce = secrets.token_bytes(NONCE_SIZE)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()

    # Write header: magic | salt | nonce
    with open(in_path, 'rb') as fin, open(out_path, 'wb') as fout:
        fout.write(MAGIC)            # magic (6 bytes)
        fout.write(salt)             # 16 bytes
        fout.write(nonce)            # 12 bytes

        # stream encryption
        while True:
            chunk = fin.read(CHUNK_SIZE)
            if not chunk:
                break
            ct = encryptor.update(chunk)
            if ct:
                fout.write(ct)

        # finalize & write tag
        encryptor.finalize()
        tag = encryptor.tag  # 16 bytes
        fout.write(tag)

def decrypt_file(in_path: str, out_path: str, password: str):
    filesize = os.path.getsize(in_path)
    header_len = len(MAGIC) + SALT_SIZE + NONCE_SIZE
    if filesize < header_len + TAG_SIZE:
        raise ValueError("Input file too small or corrupted")

    with open(in_path, 'rb') as fin:
        # Read header
        magic = fin.read(len(MAGIC))
        if magic != MAGIC:
            raise ValueError("Unrecognized file format or wrong version")

        salt = fin.read(SALT_SIZE)
        nonce = fin.read(NONCE_SIZE)

        # Read tag from file end
        fin.seek(-TAG_SIZE, os.SEEK_END)
        tag = fin.read(TAG_SIZE)

        # Now position to start of ciphertext
        fin.seek(header_len, os.SEEK_SET)
        cipher = Cipher(algorithms.AES(derive_key_from_password(password, salt, length=32)),
                        modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()

        # Read ciphertext until tag (we must not read the tag as ciphertext)
        bytes_left_for_ciphertext = filesize - header_len - TAG_SIZE
        with open(out_path, 'wb') as fout:
            remaining = bytes_left_for_ciphertext
            while remaining > 0:
                read_size = min(CHUNK_SIZE, remaining)
                chunk = fin.read(read_size)
                remaining -= len(chunk)
                if not chunk:
                    break
                pt = decryptor.update(chunk)
                if pt:
                    fout.write(pt)

            # finalize (will raise InvalidTag if tampered/wrong password)
            try:
                decryptor.finalize()
            except Exception as e:
                # If tag verification fails, delete partial output & raise
                fout.close()
                os.remove(out_path)
                raise e

if __name__=='__main__':
    pass
    # pw = generate_password()  # give this to the user securely
    # encrypt_file(r"input_mov", "input.mov.enc", pw)
    # print("Password to decrypt:", pw)
    # decrypt_file("input.mov.enc", "input_decrypted.mp4", "3jDpOVWfUs8kq1X8Iog1wFYK_GX4qsowDJOXP6OnpVQ")