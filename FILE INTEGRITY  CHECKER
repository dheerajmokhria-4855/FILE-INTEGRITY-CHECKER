import hashlib
import os

HASH_FILE = "file_hash.txt"
TARGET_FILE = "target.txt"  # Change to the file you want to monitor

def calculate_hash(filepath):
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

def load_previous_hash():
    if not os.path.exists(HASH_FILE):
        return None
    with open(HASH_FILE, "r") as f:
        return f.read().strip()

def save_hash(hash_value):
    with open(HASH_FILE, "w") as f:
        f.write(hash_value)

def main():
    if not os.path.exists(TARGET_FILE):
        print(f"Target file '{TARGET_FILE}' does not exist.")
        return

    current_hash = calculate_hash(TARGET_FILE)
    previous_hash = load_previous_hash()

    if previous_hash is None:
        print("No previous hash found. Saving current hash.")
        save_hash(current_hash)
    elif previous_hash == current_hash:
        print("File integrity OK. No changes detected.")
    else:
        print("WARNING: File integrity compromised! Hash mismatch detected.")
        save_hash(current_hash)

if __name__ == "__main__":
    main()
