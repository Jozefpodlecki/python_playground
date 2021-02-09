import json
from os import path, listdir, mkdir, chdir

def get_script_directory():
    return path.dirname(path.realpath(__file__))

def load_json(file_path):
    with open(file_path, "r", encoding="utf-8") as read_file:
        return json.load(read_file)

def save_json(file_path, data):
    with open(file_path, "w") as data_file:
        json.dump(data, data_file, indent=2)