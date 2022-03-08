import os
import pprint


def print_files_in_folder(folder: str) -> None:
    files = {}
    for _file in os.listdir(folder):
        file_path = os.path.join(folder, _file)
        files[file_path] = os.path.getmtime(file_path)

    files = sorted(files.items(), key=lambda x: x[1])
    for file_path, mtime in files:
        pprint.pprint(f"{file_path} {mtime}")
