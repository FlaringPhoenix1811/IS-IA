import os
import shutil
from datetime import datetime

class SHA256:
    def __init__(self):
        # Initial hash values (first 32 bits of the fractional parts of the square roots of the first 8 prime numbers)
        self.h = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        ]
        # K constants (first 32 bits of the fractional parts of the cube roots of the first 64 prime numbers)
        self.k = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
            0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
            0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
            0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
            0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
            0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
            0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
            0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        ]

    @staticmethod
    def _rotr(x, n):
        return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

    @staticmethod
    def _ch(x, y, z):
        return (x & y) ^ (~x & z)

    @staticmethod
    def _maj(x, y, z):
        return (x & y) ^ (x & z) ^ (y & z)

    @staticmethod
    def _sigma0(x):
        return SHA256._rotr(x, 2) ^ SHA256._rotr(x, 13) ^ SHA256._rotr(x, 22)

    @staticmethod
    def _sigma1(x):
        return SHA256._rotr(x, 6) ^ SHA256._rotr(x, 11) ^ SHA256._rotr(x, 25)

    @staticmethod
    def _gamma0(x):
        return SHA256._rotr(x, 7) ^ SHA256._rotr(x, 18) ^ (x >> 3)

    @staticmethod
    def _gamma1(x):
        return SHA256._rotr(x, 17) ^ SHA256._rotr(x, 19) ^ (x >> 10)

    def _pad_message(self, message):
        # Padding according to the SHA-256 standard
        length = len(message) * 8  # Length in bits
        message += b'\x80'
        message += b'\x00' * ((56 - (len(message) % 64)) % 64)
        message += length.to_bytes(8, byteorder='big')
        return message

    def _process_block(self, block):
        # Message schedule
        w = [0] * 64

        # Initialize the message schedule
        for t in range(0, 16):
            w[t] = int.from_bytes(block[t * 4:(t + 1) * 4], byteorder='big')

        for t in range(16, 64):
            w[t] = (SHA256._gamma1(w[t - 2]) + w[t - 7] + SHA256._gamma0(w[t - 15]) + w[t - 16]) & 0xFFFFFFFF

        # Working variables
        a, b, c, d, e, f, g, h = self.h

        # Compression function
        for t in range(64):
            t1 = h + SHA256._sigma1(e) + SHA256._ch(e, f, g) + self.k[t] + w[t]
            t2 = SHA256._sigma0(a) + SHA256._maj(a, b, c)
            h = g
            g = f
            f = e
            e = (d + t1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (t1 + t2) & 0xFFFFFFFF

        # Update hash values
        self.h[0] = (self.h[0] + a) & 0xFFFFFFFF
        self.h[1] = (self.h[1] + b) & 0xFFFFFFFF
        self.h[2] = (self.h[2] + c) & 0xFFFFFFFF
        self.h[3] = (self.h[3] + d) & 0xFFFFFFFF
        self.h[4] = (self.h[4] + e) & 0xFFFFFFFF
        self.h[5] = (self.h[5] + f) & 0xFFFFFFFF
        self.h[6] = (self.h[6] + g) & 0xFFFFFFFF
        self.h[7] = (self.h[7] + h) & 0xFFFFFFFF

    def calculate_hash(self, message):
        # Pad the message
        padded_message = self._pad_message(message)

        # Process each block
        for i in range(0, len(padded_message), 64):
            block = padded_message[i:i + 64]
            self._process_block(block)

        # Convert the final hash values to hexadecimal
        return ''.join(format(h, '08x') for h in self.h)

class VersioningTool:
    def __init__(self, base_directory):
        self.base_directory = base_directory
        self.version_directory = os.path.join(base_directory, '.versions')

        # Create version directory if it doesn't exist
        if not os.path.exists(self.version_directory):
            os.makedirs(self.version_directory)

    def create_version(self, file_path, hash_value):
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')

        # Create versioned file name
        versioned_file_name = f"{timestamp}_{hash_value}_{os.path.basename(file_path)}"

        # Copy the original file to the version directory with the versioned name
        versioned_file_path = os.path.join(self.version_directory, versioned_file_name)
        shutil.copy2(file_path, versioned_file_path)

        print(f"Version created: {versioned_file_name}")

    def update_file(self, file_path, new_content):
        with open(file_path, 'w') as file:
            file.write(new_content)

    def commit(self, file_path):
        # Calculate SHA-256 hash manually
        sha256 = SHA256()
        
        with open(file_path, 'rb') as file:
            file_content = file.read()
            
        hash_value = sha256.calculate_hash(file_content)

        # Create a new version before committing changes
        self.create_version(file_path, hash_value)

    def rollback(self, file_path, version_name):
        # Revert the file to the specified version
        versioned_file_path = os.path.join(self.version_directory, version_name)
        shutil.copy2(versioned_file_path, file_path)

if __name__ == "__main__":
    base_directory = ''
    file_path = os.path.join(base_directory, 'hello.txt')

    # Initial file creation
    with open(file_path, 'w') as file:
        file.write("Initial content")

    versioning_tool = VersioningTool(base_directory)

    while True:
        print("\nMenu:")
        print("1. Update File Content")
        print("2. Commit Changes")
        print("3. Rollback to Previous Version")
        print("4. Exit")

        choice = input("Enter your choice (1-4): ")

        if choice == '1':
            new_content = input("Enter the new content for the file: ")
            versioning_tool.update_file(file_path, new_content)
            print("File content updated.")

        elif choice == '2':
            versioning_tool.commit(file_path)
            print("Changes committed. New version created.")

        elif choice == '3':
            version_name = input("Enter the version name to rollback to: ")
            versioning_tool.rollback(file_path, version_name)
            print(f"File rolled back to version: {version_name}")

        elif choice == '4':
            print("Exiting the program.")
            break

        else:
            print("Invalid choice. Please enter a number between 1 and 4.")
