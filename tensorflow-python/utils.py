# -*- coding: utf-8 -*-

from PIL import Image,ImageDraw,ImageFont
from os import path, listdir;
import json

#font_path = "C:\\Windows\\Fonts\\mingliub.ttc"
script_directory = path.dirname(path.realpath(__file__))
font_path = path.join(script_directory, "fonts",  "HanaMinA.ttf")
image_output_directory = path.join(script_directory, "images")

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

def save_json(file_path, data):
    with open(file_path, "w") as data_file:
        json.dump(data, data_file, indent=2)

def load_texts(file_path):
    with open(file_path, "r", encoding="utf-8") as read_file:
        return json.load(read_file)

def generate_image_with_text(text, size, output_file_name):

    font_size = 70
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

    size = (300,150)

    file_path = path.join(script_directory, "data.json")
    items = load_texts(file_path)

    for item in items:
        
        text = item["text"]
        file_name = generate_id()
        image_file_path = "{}/{}.png".format(image_output_directory, file_name)

        generate_image_with_text(text, size, image_file_path)

        item["image_file_path"] = image_file_path

    file_path = path.join(script_directory, "processed_data.json")

    save_json(file_path, items)