import json
import bs4 as bs
import requests
from utils import load_json, save_json, get_script_directory
from os import path, listdir, mkdir, chdir
import uuid
import re

lookup_file_name = "lookup.json"

headers = {
    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
    "accept-encoding": "gzip, deflate, br",
    "accept-language": "pl-PL,pl;q=0.9,en-US;q=0.8,en;q=0.7",
    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.150 Safari/537.36",
}

def get_cached_json(url):

    script_directory = get_script_directory()
    chdir(script_directory)

    if path.exists(lookup_file_name):
        lookup = load_json(lookup_file_name)
    else:
        lookup = {}

    file_name = lookup.get(url)
    
    if file_name:
        with open(file_name, "rb") as file_handle:
            content = file_handle.read()
            return json.loads(content)
        
    file_name = "{}.json".format(uuid.uuid4())

    response = requests.get(url, headers)
    content = response.content

    with open(file_name, 'wb') as file_handle:
        file_handle.write(content)

    lookup[url] = file_name
    save_json(lookup_file_name, lookup)

    return json.loads(content) 

def get_cached_page(url):

    script_directory = get_script_directory()
    chdir(script_directory)

    if path.exists(lookup_file_name):
        lookup = load_json(lookup_file_name)
    else:
        lookup = {}

    file_name = lookup.get(url)
    
    if file_name:
        with open(file_name, "rb") as file_handle:
            content = file_handle.read()
            soup = bs.BeautifulSoup(content, 'lxml')
            return soup
        
    file_name = "{}.html".format(uuid.uuid4())

    response = requests.get(url, headers)
    content = response.content

    with open(file_name, 'wb') as file_handle:
        file_handle.write(content)

    lookup[url] = file_name
    save_json(lookup_file_name, lookup)

    soup = bs.BeautifulSoup(content, 'lxml')

    return soup 

def main():
    
    #// "referer": "https://www.qhanzi.com/index.html",
    content = get_cached_page("https://www.qhanzi.com/mr.html")

    radicals = {}

    for element in content.select("span[class*='mr-button']"):
        cssId = element.get("id")
        match = re.search("mr-(\d*)", cssId)

        if not match:
            print(cssId)
            continue
        
        qhanzi_radical_id = match.group(1)
        radical = element.text

        url = "https://www.qhanzi.com/qhanzimr/?buttons={}".format(qhanzi_radical_id)
        data = get_cached_json(url)

        radicals[radical] = data

    save_json("radicals_hanzi_map.json", radicals)

if __name__ == '__main__':
    main()