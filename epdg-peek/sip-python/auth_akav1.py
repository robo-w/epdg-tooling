import hashlib
import re
import sys

from auth_state_util import load_auth_state


def md5_hex_bytes(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def md5_hex(data: str) -> str:
    return hashlib.md5(data.encode("ascii")).hexdigest()


def aka_res_to_password(res_hex: str) -> bytes:
    assert re.fullmatch(r"[0-9a-fA-F]+", res_hex), f"Invalid SIM RES hex string: {res_hex}"
    assert len(res_hex) % 2 == 0, f"Invalid SIM RES hex string length: {len(res_hex)}"
    return bytes.fromhex(res_hex)


def calculate_aka_digest(username: str, realm: str, sim_res_hex: str | None, nonce_b64: str, request_uri: str,
                         method: str = "REGISTER") -> str:
    ha1_input = f"{username}:{realm}:".encode("ascii")
    if sim_res_hex is not None:
        aka_password = aka_res_to_password(sim_res_hex)
        ha1_input += aka_password
    ha1 = md5_hex_bytes(ha1_input)

    ha2_input = f"{method}:{request_uri}"
    ha2 = md5_hex(ha2_input)

    response_input = f"{ha1}:{nonce_b64}:{ha2}"
    response = md5_hex(response_input)

    return response


def test_auth_file():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <imsi> <realm> [auth_state_file]", file=sys.stderr)
        return

    file_name = "auth_state.json"
    if sys.argv[3:]:
        file_name = sys.argv[3]

    auth_state = load_auth_state(file_name)
    if not auth_state:
        print(f"Failed to load auth file '{file_name}'", file=sys.stderr)
        return

    imsi = sys.argv[1]
    realm = sys.argv[2]

    username = imsi + "@" + realm
    nonce_b64 = auth_state.get("challenge", {}).get("nonce")
    sim_res = auth_state.get("challenge", {}).get("res")
    request_uri = f"sip:{realm}"

    print(f"Input for AKAv1-MD5 from '{file_name}':")
    print(f"  imsi:         '{imsi}'")
    print(f"  realm:        '{realm}'")
    print(f"  username:     '{username}'")
    print(f"  nonce:        '{nonce_b64}'")
    print(f"  sim_res:      '{sim_res}'")
    print(f"  request_uri:  '{request_uri}'")
    response = calculate_aka_digest(username, realm, sim_res, nonce_b64, request_uri)
    print(f"Response: {response}")


if __name__ == "__main__":
    test_auth_file()
