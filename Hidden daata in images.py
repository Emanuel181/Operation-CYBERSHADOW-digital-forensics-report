import os
import sys
import argparse
import binascii
import logging
import re
from PIL import Image, UnidentifiedImageError

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

def analyze_metadata(file_path):
    try:
        with Image.open(file_path) as img:
            logging.info("Image Metadata:")
            for key, value in img.info.items():
                print(f"  {key}: {value}")
            print(f"  Format: {img.format}")
            print(f"  Size: {img.size}")
            print(f"  Mode: {img.mode}")
    except UnidentifiedImageError:
        logging.error("Unrecognized or unsupported image format.")
    except Exception as e:
        logging.error(f"Failed to extract metadata: {e}")

def extract_ascii_strings(file_path, min_length=4):
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        pattern = rb'[ -~]{' + str(min_length).encode() + rb',}'
        matches = re.findall(pattern, data)
        if matches:
            logging.info("Extracted ASCII Strings:")
            for s in matches:
                print("  " + s.decode('ascii', errors='ignore'))
        else:
            logging.info("No ASCII strings found.")
    except Exception as e:
        logging.error(f"Failed to extract strings: {e}")

def analyze_trailing_data_bmp(file_path):
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        filesize = os.path.getsize(file_path)
        if not file_path.lower().endswith('.bmp'):
            logging.warning("Trailing data analysis is designed for BMP files.")
            return
        declared_size = int.from_bytes(data[2:6], byteorder='little')
        if filesize > declared_size:
            logging.info("Trailing Data Detected:")
            print(f"  Declared BMP size: {declared_size} bytes")
            print(f"  Actual file size:  {filesize} bytes")
            extra = data[declared_size:]
            print(f"  Extra bytes found: {filesize - declared_size}")
            print(f"  First 32 bytes (hex): {binascii.hexlify(extra[:32]).decode()}")
        else:
            logging.info("No trailing data found.")
    except Exception as e:
        logging.error(f"Failed to analyze trailing data: {e}")

def main():
    parser = argparse.ArgumentParser(description="Image Forensics Tool")
    parser.add_argument("file", help="Path to the image file")
    parser.add_argument("--min-length", type=int, default=4, help="Minimum ASCII string length (default: 4)")
    parser.add_argument("--no-metadata", action='store_true', help="Skip metadata extraction")
    parser.add_argument("--no-strings", action='store_true', help="Skip ASCII string extraction")
    parser.add_argument("--check-bmp-trailing", action='store_true', help="Check for BMP trailing data")

    args = parser.parse_args()
    if not os.path.isfile(args.file):
        logging.error(f"File not found: {args.file}")
        sys.exit(1)

    logging.info(f"Analyzing file: {args.file}")
    if not args.no_metadata:
        analyze_metadata(args.file)
    if not args.no_strings:
        extract_ascii_strings(args.file, args.min_length)
    if args.check_bmp_trailing:
        analyze_trailing_data_bmp(args.file)

if __name__ == "__main__":
    main()
