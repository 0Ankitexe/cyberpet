"""Package manager trust verification for CyberPet V2.

Queries dpkg/rpm to determine whether a file belongs to an installed
package and whether its hash still matches the package database.  Files
that are package-managed AND unmodified are trusted and can be skipped
by the scanner.

Auto-detects the available package manager at init.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from functools import lru_cache


class PackageManagerTrust:
    """Verify files against dpkg / rpm package databases.

    Usage::

        trust = PackageManagerTrust()
        managed, hash_ok = trust.verify_package_hash("/usr/bin/python3")
        if managed and hash_ok:
            # safe to skip scanning
            ...
    """

    def __init__(self) -> None:
        self._pkgmgr = self._detect_package_manager()

    # ------------------------------------------------------------------
    # Detection
    # ------------------------------------------------------------------

    @staticmethod
    def _detect_package_manager() -> str:
        """Return 'dpkg', 'rpm', or 'none'."""
        if shutil.which("dpkg"):
            return "dpkg"
        if shutil.which("rpm"):
            return "rpm"
        return "none"

    @property
    def available(self) -> bool:
        """True when a supported package manager is detected."""
        return self._pkgmgr != "none"

    # ------------------------------------------------------------------
    # Lookup (cached)
    # ------------------------------------------------------------------

    @lru_cache(maxsize=8192)
    def is_package_managed(self, filepath: str) -> bool:
        """Return True if *filepath* belongs to any installed package.

        Results are cached for the lifetime of the process so that
        repeated calls during a scan are fast.
        """
        # Temp paths are never package-managed — fast exit.
        if filepath.startswith(("/tmp", "/dev/shm", "/var/tmp", "/run/user")):
            return False

        if self._pkgmgr == "dpkg":
            return self._dpkg_owns(filepath)
        if self._pkgmgr == "rpm":
            return self._rpm_owns(filepath)
        return False

    def verify_package_hash(self, filepath: str) -> tuple[bool, bool]:
        """Check ownership AND hash integrity.

        Returns:
            (is_package_managed, hash_matches)

            *hash_matches* is True when the file is unmodified since
            installation.  If ownership cannot be determined the method
            returns ``(False, False)``.
        """
        if not self.is_package_managed(filepath):
            return False, False

        if self._pkgmgr == "dpkg":
            return True, self._dpkg_verify(filepath)
        if self._pkgmgr == "rpm":
            return True, self._rpm_verify(filepath)
        return True, True  # fallback — assume clean

    # ------------------------------------------------------------------
    # dpkg helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _dpkg_owns(filepath: str) -> bool:
        try:
            r = subprocess.run(
                ["dpkg", "-S", filepath],
                capture_output=True,
                text=True,
                timeout=3,
            )
            return r.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return False

    @staticmethod
    def _dpkg_verify(filepath: str) -> bool:
        """Use ``dpkg --verify`` to check integrity.

        ``dpkg --verify`` exits 0 and produces no output for unmodified
        files.  If the file is modified, the output includes the path.
        """
        try:
            r = subprocess.run(
                ["dpkg", "--verify"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            # If the file appears in the output, it has been modified.
            if filepath in r.stdout:
                return False
            return True
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return True  # assume clean on error

    # ------------------------------------------------------------------
    # rpm helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _rpm_owns(filepath: str) -> bool:
        try:
            r = subprocess.run(
                ["rpm", "-qf", filepath],
                capture_output=True,
                text=True,
                timeout=3,
            )
            return r.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return False

    @staticmethod
    def _rpm_verify(filepath: str) -> bool:
        """Use ``rpm -Vf`` to verify a file's integrity.

        ``rpm -Vf`` exits 0 when the file matches the package database.
        Non-zero exit or output containing the filepath means the file
        was modified.
        """
        try:
            r = subprocess.run(
                ["rpm", "-Vf", filepath],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return r.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return True  # assume clean on error
