from __future__ import annotations

import base64
import os


DPAPI_PREFIX = "dpapi:v1:"
PORTABLE_PREFIX = "local:v1:"


def protect_secret(value: str | None) -> str | None:
    if value in {None, ""}:
        return None
    data = str(value).encode("utf-8")
    if os.name == "nt":
        return DPAPI_PREFIX + base64.b64encode(_dpapi_protect(data)).decode("ascii")
    # This is only obfuscation on non-Windows systems. The local-only MVP uses
    # DPAPI on its target Windows platform and documents the portable fallback.
    return PORTABLE_PREFIX + base64.b64encode(data).decode("ascii")


def reveal_secret(value: str | None) -> str | None:
    if not value:
        return None
    if value.startswith(DPAPI_PREFIX):
        encrypted = base64.b64decode(value[len(DPAPI_PREFIX):], validate=True)
        return _dpapi_unprotect(encrypted).decode("utf-8")
    if value.startswith(PORTABLE_PREFIX):
        return base64.b64decode(value[len(PORTABLE_PREFIX):], validate=True).decode("utf-8")
    # Migrate-compatible read for databases created before secret protection.
    return value


def is_protected(value: str | None) -> bool:
    if not value:
        return True
    return value.startswith((DPAPI_PREFIX, PORTABLE_PREFIX))


if os.name == "nt":
    import ctypes
    from ctypes import wintypes

    class _DataBlob(ctypes.Structure):
        _fields_ = [
            ("cbData", wintypes.DWORD),
            ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
        ]

    _crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _crypt32.CryptProtectData.argtypes = [
        ctypes.POINTER(_DataBlob), wintypes.LPCWSTR, ctypes.POINTER(_DataBlob),
        ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(_DataBlob),
    ]
    _crypt32.CryptProtectData.restype = wintypes.BOOL
    _crypt32.CryptUnprotectData.argtypes = [
        ctypes.POINTER(_DataBlob), ctypes.POINTER(wintypes.LPWSTR), ctypes.POINTER(_DataBlob),
        ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(_DataBlob),
    ]
    _crypt32.CryptUnprotectData.restype = wintypes.BOOL
    _kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    _kernel32.LocalFree.restype = ctypes.c_void_p

    def _blob(data: bytes) -> tuple[_DataBlob, ctypes.Array[ctypes.c_ubyte]]:
        buffer = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
        return _DataBlob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte))), buffer

    def _dpapi_protect(data: bytes) -> bytes:
        source, source_buffer = _blob(data)
        entropy, entropy_buffer = _blob(b"ProxyPulse local credential v1")
        output = _DataBlob()
        if not _crypt32.CryptProtectData(
            ctypes.byref(source), "ProxyPulse", ctypes.byref(entropy), None, None,
            0x1, ctypes.byref(output),
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            return ctypes.string_at(output.pbData, output.cbData)
        finally:
            _kernel32.LocalFree(output.pbData)

    def _dpapi_unprotect(data: bytes) -> bytes:
        source, source_buffer = _blob(data)
        entropy, entropy_buffer = _blob(b"ProxyPulse local credential v1")
        output = _DataBlob()
        description = wintypes.LPWSTR()
        if not _crypt32.CryptUnprotectData(
            ctypes.byref(source), ctypes.byref(description), ctypes.byref(entropy),
            None, None, 0x1, ctypes.byref(output),
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            return ctypes.string_at(output.pbData, output.cbData)
        finally:
            if description:
                _kernel32.LocalFree(description)
            _kernel32.LocalFree(output.pbData)
else:
    def _dpapi_protect(data: bytes) -> bytes:  # pragma: no cover - Windows-only path
        raise RuntimeError("DPAPI is only available on Windows")

    def _dpapi_unprotect(data: bytes) -> bytes:  # pragma: no cover - Windows-only path
        raise RuntimeError("DPAPI-protected credentials can only be opened on Windows")
