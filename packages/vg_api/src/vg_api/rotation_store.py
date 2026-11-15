"""Linux single-owner encrypted rotation state, using installed PyCryptodome AES-GCM.

Key custody is external: callers supply a 32-byte key from approved secret storage.
No key creation/storage, real account enrollment or background task is automatic.
"""

import fcntl
import os
import stat
import tempfile
from pathlib import Path
from threading import RLock

from Crypto.Cipher import AES

MAGIC = b"VaultGateRotation-v1\x00"
MAX_BYTES = 8 * 1024 * 1024


class EncryptedRotationStore:
    """Exclusive process-lifetime lock plus atomic encrypted snapshot replacement.

    Directory must already exist, be owner-only, outside repo/shared mounts.
    Never close until the worker and all broker callers have stopped. Store methods
    fail after close. This is not KMS, HA storage, or rollback-resistant storage.
    """

    def __init__(self, directory: Path, key: bytes):
        if len(key) != 32:
            raise ValueError("A 32-byte vault key is required")
        directory = directory.absolute()
        if directory.resolve() != directory:
            raise ValueError("Vault directory must not traverse symlinks")
        info = directory.stat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("Vault directory must be owner-only")
        self._path = directory / "rotation.enc"
        self._key = key
        self._lock = RLock()
        self._closed = False
        self._fd = os.open(
            directory / "rotation.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600
        )
        try:
            self._check_file(self._fd)
            fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except Exception:
            os.close(self._fd)
            raise ValueError("Rotation store is unsafe or already in use") from None

    @staticmethod
    def _check_file(fd: int) -> None:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_mode & 0o077
            or info.st_nlink != 1
        ):
            raise ValueError("Unsafe vault file")

    def _check_open(self) -> None:
        if self._closed:
            raise ValueError("Rotation store is closed")

    def load(self) -> bytes | None:
        with self._lock:
            self._check_open()
            try:
                fd = os.open(self._path, os.O_RDONLY | os.O_NOFOLLOW)
            except FileNotFoundError:
                return None
            try:
                self._check_file(fd)
                with os.fdopen(fd, "rb", closefd=False) as stream:
                    payload = stream.read(MAX_BYTES + 1)
                if (
                    len(payload) > MAX_BYTES
                    or len(payload) < len(MAGIC) + 32
                    or not payload.startswith(MAGIC)
                ):
                    raise ValueError("Invalid encrypted state")
                offset = len(MAGIC)
                cipher = AES.new(self._key, AES.MODE_GCM, nonce=payload[offset : offset + 16])
                cipher.update(MAGIC)
                return cipher.decrypt_and_verify(
                    payload[offset + 32 :], payload[offset + 16 : offset + 32]
                )
            except Exception:
                raise ValueError("Encrypted rotation state unavailable") from None
            finally:
                os.close(fd)

    def save(self, data: bytes) -> None:
        with self._lock:
            self._check_open()
            if len(data) + len(MAGIC) + 32 > MAX_BYTES:
                raise ValueError("Rotation state too large")
            cipher = AES.new(self._key, AES.MODE_GCM)
            cipher.update(MAGIC)
            ciphertext, tag = cipher.encrypt_and_digest(data)
            payload = MAGIC + cipher.nonce + tag + ciphertext
            fd, filename = tempfile.mkstemp(prefix=".rotation-", dir=self._path.parent)
            try:
                with os.fdopen(fd, "wb") as stream:
                    stream.write(payload)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(filename, self._path)
                directory_fd = os.open(self._path.parent, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            finally:
                if os.path.exists(filename):
                    os.unlink(filename)

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._closed = True
                self._key = b""  # Best effort only; Python cannot guarantee memory erasure.
                fcntl.flock(self._fd, fcntl.LOCK_UN)
                os.close(self._fd)
