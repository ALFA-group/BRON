import json
import gzip
import argparse

"""
Decompresses GZ file to JSON file
"""


def decompress_gz_to_json(gz_path, save_path):
    with gzip.open(gz_path, "rt", encoding="utf-8") as f:
        decompressed = json.load(f)

    with open(save_path, "w") as f:
        f.write(json.dumps(decompressed, indent=4, sort_keys=True))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Decompress GZ file to JSON file")
    parser.add_argument(
        "--gz_path",
        type=str,
        required=True,
        help="Location of .gz file to be decompressed",
    )
    parser.add_argument(
        "--save_path", type=str, required=True, help="Location to save file as .json"
    )
    args = parser.parse_args()
    gz_path_ = args.gz_path
    save_path_ = args.save_path
    decompress_gz_to_json(gz_path_, save_path_)
