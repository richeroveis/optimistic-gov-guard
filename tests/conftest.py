"""Windows compatibility for gltest direct-mode message injection.

gltest's direct loader injects the transaction message by pointing fd 0 at an
encoded temp file and then immediately calls os.unlink on that file. On native
Windows a file still held open by fd 0 cannot be deleted, so the library raises
PermissionError (WinError 32) even though the injection itself succeeded.

This module wraps the single loader call site so a failed unlink is deferred
and retried on the next deploy (by then earlier temp files have been released
when the VM restored the original stdin). Behaviour on platforms where the
original code path succeeds is unchanged: the unlink still runs immediately.
Only temp-file cleanup is delayed, never contract semantics.
"""

import atexit
import os

from gltest.direct import loader as _gltest_loader

_original_inject = _gltest_loader._inject_message_to_fd0
_deferred_unlinks: list[str] = []


def _flush_deferred_unlinks() -> None:
    remaining: list[str] = []
    for path in _deferred_unlinks:
        try:
            os.unlink(path)
        except OSError:
            remaining.append(path)
    _deferred_unlinks[:] = remaining


def _windows_safe_inject(vm):
    # Retry cleanup of temp files whose unlink was refused while fd 0 held them.
    _flush_deferred_unlinks()

    real_unlink = os.unlink

    def _defer_on_busy(path, *args, **kwargs):
        try:
            return real_unlink(path, *args, **kwargs)
        except PermissionError:
            _deferred_unlinks.append(str(path))
            return None

    # Scoped strictly to the library call below; restored in finally.
    os.unlink = _defer_on_busy
    try:
        return _original_inject(vm)
    finally:
        os.unlink = real_unlink


_gltest_loader._inject_message_to_fd0 = _windows_safe_inject
atexit.register(_flush_deferred_unlinks)
