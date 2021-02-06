# -*- coding: utf-8 -*-

from PIL import Image,ImageDraw,ImageFont
from os import path, listdir, mkdir, chdir
import itertools
import json

#font_path = "C:\\Windows\\Fonts\\mingliub.ttc"

def get_script_directory():
    return path.dirname(path.realpath(__file__))

def static_vars(**kwargs):
    def decorate(func):
        for k in kwargs:
            setattr(func, k, kwargs[k])
        return func
    return decorate

@static_vars(counter=0)
def generate_id():
    generate_id.counter += 1
    return generate_id.counter

def get_cjk():
    start = int("4E00", 16)
    end = int("9FFF", 16)

    for code in range(start, end):
        yield chr(code)

def save_cjk():
    items = []

    for char in itertools.islice(get_cjk(), 1000):
        item = {
            "text": char
        }
        items.append(item)

    file_path = path.join(script_directory, "data.json")
    save_json(file_path, items)

def save_json(file_path, data):
    with open(file_path, "w") as data_file:
        json.dump(data, data_file, indent=2)

def load_json(file_path):
    with open(file_path, "r", encoding="utf-8") as read_file:
        return json.load(read_file)

def generate_image_with_text(text, size, output_file_name, font_size, font_path):

    width, height = size

    image = Image.new(mode = "RGB", size = size, color = "white")
    #ImageFont.load(font_path)
    #font = ImageFont.load_default().font
    font = ImageFont.truetype(font_path, font_size, encoding = "unic")

    draw = ImageDraw.Draw(image)
    text_width, text_height  = draw.textsize(text, font=font)
    position = ((width - text_width) / 2, (height - text_height) / 2)
    draw.text(position, text, font=font, fill="black")

    image.save(output_file_name)

if __name__ == '__main__':

    font_size = 100
    size = (150, 150)
    
    script_directory = get_script_directory()
    chdir(script_directory)
    image_output_directory = path.join(script_directory, "images")

    if not path.exists(image_output_directory):
        mkdir(image_output_directory)

    font_path = path.join(script_directory, "fonts",  "HanaMinA.ttf")

    file_path = path.join(script_directory, "data.json")
    items = load_json(file_path)
    index = 0

    for item in items:
        
        text = item["text"]
        file_name = generate_id()
        image_file_path = path.join(image_output_directory, "{}.png".format(file_name))

        generate_image_with_text(text, size, image_file_path, font_size, font_path)

        item["image_file_path"] = path.relpath(image_file_path)
        item["label"] = index
        index += 1

    file_path = path.join(script_directory, "processed_data.json")

    save_json(file_path, items)