# hardcoded_secret_vuln.py

# Hardcoded secrets
API_KEY = "sk_test_1234567890abcdef"
DB_PASSWORD = "SuperSecretPassword123!"

def connect():
    print("Connecting with password:", DB_PASSWORD)

if __name__ == "__main__":
    connect()
