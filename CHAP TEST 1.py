import hashlib
import hmac
import secrets

def compute_response(password: str, challenge: str, method: str = "sha256") -> str:
    data = (password + challenge).encode("utf-8")
    if method.lower() == "md5":
        return hashlib.md5(data).hexdigest()
    return hashlib.sha256(data).hexdigest()

def server_verify(stored_password: str, challenge: str, client_response: str, method: str = "sha256") -> bool:
    expected = compute_response(stored_password, challenge, method)
    return hmac.compare_digest(expected, client_response)

def main():
    print("\n=== CHAP Authentication Simulation ===")

    # Fully random challenge for realistic CHAP
    challenge = secrets.token_hex(8)
    print(f"\n[Server] Generated challenge: {challenge}")

    # Stored user credentials
    stored_username = "Bestin"
    stored_password = "s3cr3tP@ss"

    # Client input
    username = input("\n[Client] Enter your username: ").strip()
    password = input("[Client] Enter your password: ").strip()
    method = input("[Client] Choose hashing (sha256/md5) [default=sha256]: ").strip().lower() or "sha256"

    # Client computes response
    client_response = compute_response(password, challenge, method)
    print("\n[Client] Sending username and hashed response to server...")

    # Server verifies
    print(f"\n[Server] Verifying user '{username}'...")
    if username == stored_username and server_verify(stored_password, challenge, client_response, method):
        print("\n✅ Authentication SUCCESS!")
    else:
        print("\n❌ Authentication FAILED!")

    print("\n--- End of CHAP Demo ---\n")

if __name__ == "__main__":
    main()

