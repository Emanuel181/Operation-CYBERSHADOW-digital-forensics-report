import os
import argparse
import logging
import string
import shutil
import tempfile
from pathlib import Path
from itertools import product, cycle


logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

# Attempt to import py7zr, providing a fallback if not available
try:
    import py7zr

    _7Z_SUPPORT_AVAILABLE = True
except ImportError:
    _7Z_SUPPORT_AVAILABLE = False
    logging.warning("py7zr library not found. .7z archives will be identified but NOT extracted.")

# --- Character Sets and Constants ---
# Set of printable ASCII characters for text detection, including common whitespace
_PRINTABLE_CHARS_SET = set(bytes(string.printable, 'ascii'))
# ASCII values for digits '0' through '9'
_ASCII_DIGIT_VALUES = set(range(0x30, 0x3A))


# --- Core Transformation and Analysis Functions ---

def apply_xor_cipher(byte_sequence: bytes, cipher_key: tuple[int, int]) -> bytes:
    """
    Applies a two-byte XOR cipher cyclically to the given byte sequence.
    """
    transformed_bytes = bytearray()
    key_cycle = cycle(cipher_key)  # Create an infinite iterator for the key bytes

    for byte_value in byte_sequence:
        current_key_byte = next(key_cycle)
        transformed_bytes.append(byte_value ^ current_key_byte)  # XOR operation
    return bytes(transformed_bytes)  # Convert mutable bytearray back to immutable bytes


def generate_xor_key_candidates(filter_for_digits: bool = False) -> list[tuple[int, int]]:
    """
    Generates potential 2-byte XOR keys.
    If 'filter_for_digits' is True, at least one byte in the key must be an ASCII digit.
    Otherwise, all 65,536 possible 2-byte keys are generated.
    """
    candidate_keys = []
    # Using itertools.product to generate all 256x256 pairs more concisely
    for byte1, byte2 in product(range(256), repeat=2):
        if filter_for_digits:
            # Check if either byte is an ASCII digit
            if byte1 in _ASCII_DIGIT_VALUES or byte2 in _ASCII_DIGIT_VALUES:
                candidate_keys.append((byte1, byte2))
        else:
            # Add all possible 2-byte combinations
            candidate_keys.append((byte1, byte2))
    return candidate_keys


def evaluate_for_plaintext(binary_data: bytes, sample_limit: int = 500, required_ratio: float = 0.85) -> bool:
    """
    Assesses if a binary data block is likely plaintext based on the density of printable characters.
    An empty input or sample means it's not considered text.
    """
    if not binary_data:
        return False

    # Take a sample to avoid processing very large files entirely for this heuristic
    sample_to_check = binary_data[:sample_limit]
    if not sample_to_check:  # Handle case where data is shorter than sample_limit but empty
        return False

    printable_count = 0
    for byte_item in sample_to_check:
        if byte_item in _PRINTABLE_CHARS_SET:
            printable_count += 1

    character_ratio = printable_count / len(sample_to_check)
    return character_ratio > required_ratio


# Dictionary of common file magic numbers to their standard extensions
_MAGIC_NUMBERS_TO_EXTENSIONS = {
    b"\x50\x4B\x03\x04": "zip",  # ZIP archive (also Office OpenXML, JAR)
    b"\x89PNG\r\n\x1a\n": "png",  # PNG image
    b"\xFF\xD8\xFF": "jpg",  # JPEG image
    b"%PDF-": "pdf",  # PDF document
    b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1": "doc_xls_ppt",  # MS Office Legacy (OLE CFBF)
    b"MZ": "exe_dll",  # Windows Executable (EXE/DLL)
    b"\x7FELF": "elf",  # ELF Executable
    b"GIF87a": "gif",  # GIF image
    b"GIF89a": "gif",  # GIF image
    b"\x42\x4D": "bmp",  # BMP image
    b"\x37\x7A\xBC\xAF\x27\x1C": "7z",  # 7Z archive
    b"Rar!\x1A\x07\x00": "rar",  # RAR archive (old)
    b"Rar!\x1A\x07\x01\x00": "rar",  # RAR archive (new)
    b"\x1F\x8B": "gz",  # GZIP archive
    b"BZh": "bz2_archive",  # BZIP2 archive (can be tar.bz2 or standalone)
    b"RIFF": "riff_media",  # Common for AVI, WAV, WEBP (requires deeper parsing)
    b"ID3": "mp3",  # MP3 audio (ID3 tag)
    b"fLaC": "flac",  # FLAC audio
    b"OggS": "ogg",  # OGG audio
    b"%!PS-Adobe": "ps",  # PostScript document
    b"CWS": "swf",  # Shockwave Flash
    b"FWS": "swf",  # Shockwave Flash (uncompressed)
    b"SQLite format 3\x00": "sqlite",  # SQLite Database
}


def deduce_file_extension_by_signature(initial_bytes: bytes) -> str | None:
    """
    Attempts to identify file type by matching known magic numbers.
    Prioritizes more specific matches.
    """
    # Specific RIFF checks if 'RIFF' header is present
    if initial_bytes.startswith(b'RIFF') and len(initial_bytes) >= 12:
        if initial_bytes[8:12] == b'WEBP': return 'webp'
        if initial_bytes[8:12] == b'AVI ': return 'avi'
        if initial_bytes[8:12] == b'WAVE': return 'wav'

    # General magic number checks
    for magic, ext in _MAGIC_NUMBERS_TO_EXTENSIONS.items():
        if initial_bytes.startswith(magic):
            # Special handling for more complex cases or initial generic matches
            if ext == "mp3" and not (initial_bytes[0] == 0xFF and (initial_bytes[1] & 0xE0) == 0xE0):
                continue  # Ensure it's not just ID3 but also an MP3 frame header if checking broadly
            if ext == "bz2_archive" and len(initial_bytes) >= 512 and initial_bytes[257:262] == b'ustar':
                return 'tar.bz2'  # It's a tar.bz2, not just raw bz2
            # For general bz2, just return bz2 if no ustar (handled outside this function if it's standalone)

            # More granular checks for video types with 'ftyp'
            if len(initial_bytes) >= 12 and initial_bytes[4:8] == b'ftyp':
                major_brand = initial_bytes[8:12]
                if major_brand in [b'isom', b'iso2', b'mp41', b'mp42', b'mp4f', b'M4A ', b'M4V ']:
                    return 'mp4'
                elif major_brand == b'qt  ':
                    return 'mov'
                else:
                    return f'mp4_mov_ftyp({major_brand.decode(errors="ignore")})'  # More specific sub-type

            # Proprietary formats (example from Chapter 1)
            if initial_bytes.startswith(b'RTBTCore'): return "proprietary_rtb"
            if initial_bytes.startswith(b'sdPC'): return "proprietary_sdpc"

            return ext
    return None  # No specific magic number match


# --- Main Execution Flow ---

def execute_decryption_and_identification():
    """
    Main function to parse arguments, perform XOR decryption attempts,
    identify file types, and save valid results.
    """
    parser = argparse.ArgumentParser(
        description="A utility to attempt 2-byte XOR decryption on a binary file, "
                    "identifying and saving potential recovered files based on their content signatures."
    )
    parser.add_argument(
        '--input_path',
        type=Path,
        required=True,
        help='Absolute or relative path to the binary input file (e.g., data.bin).'
    )
    parser.add_argument(
        '--output_directory',
        type=Path,
        default=Path('./decrypted_artifacts'),
        help='Directory where successfully decrypted files will be saved. Will be created if non-existent.'
    )
    parser.add_argument(
        '--limit_results',
        type=int,
        default=5,
        help='Sets a maximum number of identifiable decrypted files to save before stopping. Use 0 for no limit.'
    )
    parser.add_argument(
        '--prioritize_digit_keys',
        action='store_true',
        help='If set, the key generation will prioritize pairs where at least one byte is an ASCII digit (0-9).'
    )
    parser.add_argument(
        '--text_scan_sample_len',
        type=int,
        default=1024,  # Increased sample size for text check
        help='Number of bytes to sample from the beginning of decrypted data for text detection.'
    )
    parser.add_argument(
        '--text_min_ratio',
        type=float,
        default=0.9,  # Increased threshold for text purity
        help='Minimum ratio of printable characters for data to be considered plaintext.'
    )

    arguments = parser.parse_args()

    # --- Pre-execution Validation ---
    if not arguments.input_path.is_file():
        logging.error(f"Error: Specified input file '{arguments.input_path}' does not exist or is not a file.")
        return

    try:
        arguments.output_directory.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        logging.error(f"Critical: Failed to create output directory '{arguments.output_directory}': {e}")
        return

    logging.info(f"Loading binary content from: '{arguments.input_path}'...")
    try:
        raw_binary_content = arguments.input_path.read_bytes()
    except Exception as e:
        logging.error(f"Failed to read input file '{arguments.input_path}': {e}")
        return
    logging.info(f"Successfully loaded {len(raw_binary_content)} bytes.")

    # --- Key Generation ---
    logging.info(
        f"Generating potential XOR key pairs {'(digit-filtered)' if arguments.prioritize_digit_keys else '(all combinations)'}...")
    prospective_keys = generate_xor_key_candidates(arguments.prioritize_digit_keys)
    logging.info(f"Prepared to test {len(prospective_keys)} key combinations.")

    # --- Decryption and Identification Loop ---
    successful_decryptions_count = 0
    for current_key_pair in prospective_keys:
        transformed_content = apply_xor_cipher(raw_binary_content, current_key_pair)

        # Determine file type based on headers/signatures
        deduced_extension = deduce_file_extension_by_signature(
            transformed_content[:512])  # Pass enough bytes for header checks

        # If no binary signature, attempt text heuristic
        if deduced_extension is None:
            if evaluate_for_plaintext(transformed_content, arguments.text_scan_sample_len, arguments.text_min_ratio):
                deduced_extension = "txt"

        if deduced_extension:
            hex_key_representation = f'{current_key_pair[0]:02x}{current_key_pair[1]:02x}'
            output_filename = f'recovered_data_{hex_key_representation}.{deduced_extension}'
            output_full_path = arguments.output_directory / output_filename

            try:
                output_full_path.write_bytes(transformed_content)
                logging.info(
                    f"Recovered: '{output_filename}' using key {current_key_pair} (ASCII: '{chr(current_key_pair[0])}', '{chr(current_key_pair[1])}')")
                successful_decryptions_count += 1
            except Exception as e:
                logging.error(f"Failed to write recovered file '{output_filename}': {e}")

            if arguments.limit_results > 0 and successful_decryptions_count >= arguments.limit_results:
                logging.info(f"Reached limit of {arguments.limit_results} recovered files. Stopping scan.")
                break  # Exit the loop early

    if successful_decryptions_count == 0:
        logging.info("No identifiable file types were recovered with the tested keys and specified heuristics.")
    else:
        logging.info(
            f"Decryption process completed. Successfully recovered {successful_decryptions_count} files to '{arguments.output_directory}'.")


if __name__ == "__main__":
    execute_decryption_and_identification()
