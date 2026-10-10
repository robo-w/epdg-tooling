import json
import os
import sys


def load_auth_state(auth_file: str | None) -> dict | None:
    if auth_file is None:
        return None

    if not os.path.exists(auth_file):
        print(f"Auth file '{auth_file}' does not exist. Starting with empty auth state.", file=sys.stderr)
        return {}

    try:
        with open(auth_file, "r") as f:
            auth_state = json.load(f)
            print(f"Loaded auth state from '{auth_file}'.", file=sys.stderr)
            return auth_state
    except Exception as e:
        print(f"Failed to load auth state from '{auth_file}': {e}. Starting with empty auth state.", file=sys.stderr)
        return {}


def save_auth_state(auth_file: str, auth_state: dict) -> None:
    try:
        with open(auth_file, "w") as f:
            json.dump(auth_state, f, indent=2)
            print(f"Saved auth state to '{auth_file}'.", file=sys.stderr)
    except Exception as e:
        print(f"Failed to save auth state to '{auth_file}': {e}.", file=sys.stderr)


if __name__ == "__main__":
    raise RuntimeError("This module is not intended to be run directly. Please import it in your application.")
