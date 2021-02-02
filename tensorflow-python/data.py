from PIL import Image
from os import path, listdir;
import numpy as np

script_directory = path.dirname(path.realpath(__file__))
target_directory = "../bin/Debug/netcoreapp3.1/output"
images_path = path.realpath(path.join(script_directory, target_directory))

def get_train_data():
    for file_name in listdir(images_path):
        file_path = path.join(images_path, file_name)

        image = Image.open(file_path)
        image = np.array(image)
        image *= 255.0/image.max()
        # image = image.resize(*params)