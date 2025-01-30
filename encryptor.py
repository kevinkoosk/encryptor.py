import sys
import argparse
import hashlib
import os
from itertools import cycle
try:
    from tqdm import tqdm
except ImportError:
    tqdm = None

class XorCrypt:
    def __init__(self, key, passes=1):
        self.key = self._process_key(key)
        self.passes = passes
    
    @staticmethod
    def _process_key(key):
        """Create stronger key using key stretching"""
        return hashlib.sha256(key.encode()).digest()
    
    def _xor_operation(self, data):
        """Perform XOR with key cycling"""
        return bytes([a ^ b for a, b in zip(data, cycle(self.key))])
    
    def transform(self, data, progress=False):
        """Multiple pass encryption/decryption with progress"""
        result = data
        range_gen = range(self.passes)
        if progress and tqdm:
            range_gen = tqdm(range_gen, desc="Processing passes", unit="pass")
        
        for _ in range_gen:
            result = self._xor_operation(result)
        return result

class FileProcessor:
    def __init__(self, mode, input_file, output_file, key, 
                 passes=1, checksum=False, key_file=None):
        self.mode = mode
        self.input_file = input_file
        self.output_file = output_file
        self.key = self._get_key(key, key_file)
        self.passes = passes
        self.checksum = checksum
        self.crypt = XorCrypt(self.key, passes)
        
        # Fixed checksum file naming logic
        if checksum:
            if mode == 'encrypt':
                # For encryption: checksum based on output file
                self.checksum_file = f"checksum-{os.path.basename(output_file)}"
            else:
                # For decryption: checksum based on input file (original encrypted file)
                self.checksum_file = f"checksum-{os.path.basename(input_file)}"
        else:
            self.checksum_file = None
    
    def _write_checksum(self, data):
        """Write checksum to separate file"""
        checksum = hashlib.sha256(data).hexdigest()
        with open(self.checksum_file, 'w') as f:
            f.write(checksum)
    
    def _verify_checksum(self, data):
        """Verify checksum from separate file"""
        try:
            with open(self.checksum_file, 'r') as f:
                stored_checksum = f.read().strip()
            
            current_checksum = hashlib.sha256(data).hexdigest()
            
            if stored_checksum != current_checksum:
                sys.exit(f"Checksum mismatch!\nStored: {stored_checksum}\nActual: {current_checksum}")
        
        except FileNotFoundError:
            sys.exit(f"Checksum file {self.checksum_file} not found")

    def process(self):
        try:
            with open(self.input_file, 'rb') as f:
                data = f.read()
            
            if self.mode == 'encrypt':
                # Process data and write checksum separately
                processed = self.crypt.transform(data, progress=True)
                output = processed.hex().encode()
                
                with open(self.output_file, 'wb') as f:
                    f.write(output)
                
                if self.checksum:
                    self._write_checksum(data)
                    print(f"Checksum saved to: {self.checksum_file}")
            
            elif self.mode == 'decrypt':
                # Process normally then verify checksum
                processed = self.crypt.transform(bytes.fromhex(data.decode()), progress=True)
                
                with open(self.output_file, 'wb') as f:
                    f.write(processed)
                
                if self.checksum:
                    self._verify_checksum(processed)
                    print("Checksum verification passed")
            
            print(f"\nSuccess: {self.mode.capitalize()}ed {self.input_file} -> {self.output_file}")
        
        except ValueError as ve:
            if "non-hexadecimal number" in str(ve):
                sys.exit("Invalid encrypted file format. Corrupted or missing checksum file?")
            raise
        except Exception as e:
            sys.exit(f"Error: {str(e)}")
            
    @staticmethod
    def _get_key(key, key_file):
        """Get key from either CLI or file"""
        if key_file:
            try:
                with open(key_file, 'r') as f:
                    return f.read().strip()
            except FileNotFoundError:
                sys.exit(f"Error: Key file {key_file} not found")
        return key
    
    def _calculate_checksum(self, data):
        return hashlib.sha256(data).hexdigest()
    

def main():
    parser = argparse.ArgumentParser(
        description="Advanced File Encryption Tool (XOR-based)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    # Core arguments
    parser.add_argument('mode', choices=['encrypt', 'decrypt'], 
                       help="Operation mode")
    parser.add_argument('input_file', help="Input file path")
    parser.add_argument('output_file', help="Output file path")
    
    # Key options
    key_group = parser.add_mutually_exclusive_group(required=True)
    key_group.add_argument('-k', '--key', help="Encryption/decryption key")
    key_group.add_argument('-K', '--key-file', 
                          help="File containing encryption key")
    
    # Security options
    parser.add_argument('-p', '--passes', type=int, default=3,
                       help="Number of encryption passes")
    parser.add_argument('-c', '--checksum', action='store_true',
                       help="Add integrity checks (SHA-256)")
    
    # Optional features
    parser.add_argument('--no-progress', action='store_true',
                       help="Disable progress indicators")
    
    args = parser.parse_args()
    
    try:
        processor = FileProcessor(
            mode=args.mode,
            input_file=args.input_file,
            output_file=args.output_file,
            key=args.key,
            passes=args.passes,
            checksum=args.checksum,
            key_file=args.key_file
        )
        processor.process()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(1)

if __name__ == "__main__":
    try:
        from colorama import init, Fore
        init()
        SUCCESS = Fore.GREEN
        WARNING = Fore.YELLOW
        ERROR = Fore.RED
    except ImportError:
        SUCCESS = WARNING = ERROR = ""
    
    main()
