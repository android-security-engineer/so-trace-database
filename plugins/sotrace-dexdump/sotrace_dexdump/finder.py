"""Locate the dexdump binary from Android SDK build-tools or PATH."""

from __future__ import annotations

import glob
import os
import shutil
from typing import Optional


class DexdumpFinder:
    """Find the ``dexdump`` binary that ships with Android SDK build-tools.

    Search order:
    1. ``$ANDROID_HOME/build-tools/*/dexdump``   (newest version wins)
    2. ``$PATH``
    3. ``/usr/lib/android-sdk/build-tools/*/dexdump``
    4. ``/opt/android-sdk/build-tools/*/dexdump``
    """

    def find_dexdump(self) -> str:
        """Return the absolute path to a usable ``dexdump`` binary.

        Raises:
            FileNotFoundError: with an actionable help message if not found.
        """
        candidate = (
            self._from_android_home()
            or self._from_path()
            or self._from_common_locations()
        )
        if candidate:
            return candidate
        raise FileNotFoundError(
            "dexdump not found.\n"
            "\n"
            "Install Android SDK build-tools and point ANDROID_HOME at the SDK root:\n"
            "  export ANDROID_HOME=$HOME/Android/Sdk\n"
            "\n"
            "Or on Debian/Ubuntu:\n"
            "  sudo apt-get install android-sdk-build-tools\n"
            "\n"
            "Or pass the binary path directly:\n"
            "  python sotrace-dexdump.py classes.dex --dexdump /path/to/dexdump"
        )

    # ------------------------------------------------------------------
    # Private search strategies
    # ------------------------------------------------------------------

    @staticmethod
    def _from_android_home() -> Optional[str]:
        """Glob $ANDROID_HOME/build-tools/*/dexdump and return newest match."""
        android_home = os.environ.get("ANDROID_HOME", "").strip()
        if not android_home:
            return None
        pattern = os.path.join(android_home, "build-tools", "*", "dexdump")
        matches = [
            p for p in glob.glob(pattern)
            if os.path.isfile(p) and os.access(p, os.X_OK)
        ]
        if not matches:
            return None
        # Sort descending on the version directory name (lexicographic ≈ semver)
        matches.sort(key=lambda p: os.path.basename(os.path.dirname(p)), reverse=True)
        return matches[0]

    @staticmethod
    def _from_path() -> Optional[str]:
        """Check whether ``dexdump`` is already on $PATH."""
        return shutil.which("dexdump")

    @staticmethod
    def _from_common_locations() -> Optional[str]:
        """Search well-known Linux SDK installation directories."""
        patterns = [
            "/usr/lib/android-sdk/build-tools/*/dexdump",
            "/opt/android-sdk/build-tools/*/dexdump",
            "/usr/local/android-sdk/build-tools/*/dexdump",
        ]
        for pattern in patterns:
            matches = [
                p for p in glob.glob(pattern)
                if os.path.isfile(p) and os.access(p, os.X_OK)
            ]
            if matches:
                matches.sort(
                    key=lambda p: os.path.basename(os.path.dirname(p)),
                    reverse=True,
                )
                return matches[0]
        return None
