"""Minimum Python version enforcement."""

import sys


def check_python_version(minimum: tuple[int, int] = (3, 10)) -> None:
    if sys.version_info < minimum:
        print(
            f"PHP2Shell Sentinel requires Python {minimum[0]}.{minimum[1]}+. "
            f"You are running {sys.version}.",
            file=sys.stderr,
        )
        sys.exit(1)
