from PIL import Image
from os import path, listdir;
from utils import load_json
import numpy as np
import json
import random

script_directory = path.dirname(path.realpath(__file__))
target_directory = "images"
images_path = path.realpath(path.join(script_directory, target_directory))

def get_file_name_without_ext(file_path):
    return path.splitext(file_path)[0]

def get_train_data(
    items,
    image_width,
    image_height,
    channels_count, batch_size):

    labels_dict = {item["label"]: index for index, item in enumerate(items)}
    start_index = 0
    end_index = batch_size - 1 

    while True:

        batch = np.empty((batch_size, image_width, image_height, channels_count))
        labels = np.empty(batch_size, dtype=np.int32)
        index = 0
        sample = items[start_index:end_index]
        start_index = end_index
        end_index = end_index + batch_size

        for item in sample:

            image_file_path = item["image_file_path"]
            label = labels_dict[item["label"]]

            image = Image.open(image_file_path)
            image = np.array(image)
            image = image.astype(float)
            image *= 255.0 / image.max()

            batch[index] = image
            labels[index] = np.array(label)
            index = index + 1
        
        yield (batch, labels)
        # image = image.resize(*params)