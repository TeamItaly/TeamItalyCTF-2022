#!/usr/bin/env python3
import os, subprocess, base64, binascii, filetype, zipfile


BANNER = """
_|
    _|_|_|  _|_|      _|_|_|    _|_|_|    _|_|
_|  _|    _|    _|  _|    _|  _|    _|  _|_|_|_|
_|  _|    _|    _|  _|    _|  _|    _|  _|
_|  _|    _|    _|    _|_|_|    _|_|_|    _|_|_|
                                    _|
                                _|_|

            _|
  _|_|_|  _|_|_|_|    _|_|    _|  _|_|    _|_|
_|_|        _|      _|    _|  _|_|      _|_|_|_|
    _|_|    _|      _|    _|  _|        _|
_|_|_|        _|_|    _|_|    _|          _|_|_|

"""
IMAGES_PATH = "./images"


def menu():
    print()
    print("1. Upload an image")
    print("2. Download an image")
    print("3. Delete an image")
    print("4. Upload multiple images")
    print("5. Exit")
    print()
    print("Insert your choice")
    try:
        return int(input("> "))
    except ValueError:
        return -1


def upload_image():
    name = input("Name for your image: ")

    encoded_content = input("Base64-encoded image: ")
    try:
        content = base64.b64decode(encoded_content)
    except binascii.Error:
        print("Invalid base64!")
        return

    if content == b"":
        print("Empty file!")
        return

    if not filetype.is_image(content):
        print("Only image files are allowed!")
        return

    with open(os.path.join(IMAGES_PATH, name), "wb") as file:
        file.write(content)


def download_image():
    images = os.listdir(IMAGES_PATH)

    for i, name in enumerate(images):
        print(f"{i}. {name}")
    print()

    print("Select which image to download")
    try:
        selection = int(input("> "))
        path = os.path.join(IMAGES_PATH, images[selection])
    except:
        print("Invalid selection!")
        return

    with open(path, "rb") as file:
        image = file.read()

    print("Here is your image")
    print(base64.b64encode(image).decode())


def delete_image():
    images = os.listdir(IMAGES_PATH)

    for i, name in enumerate(images):
        print(f"{i}. {name}")
    print()

    print("Select which image to delete")
    try:
        selection = int(input("> "))
        path = os.path.join(IMAGES_PATH, images[selection])
    except:
        print("Invalid selection!")
        return

    os.remove(path)
    print("Image successfully deleted!")


def upload_multiple_images():
    path = "/tmp/images.zip"

    encoded_content = input("Base64-encoded zip: ")
    try:
        with open(path, "wb+") as file:
            content = base64.b64decode(encoded_content)
            file.write(content)

            # mamma mia, we don't want symlinks!
            for zipinfo in zipfile.ZipFile(file).infolist():
                if zipinfo.external_attr >> 16:
                    print("Hacker detected!!")
                    return
    except zipfile.BadZipFile:
        print("Invalid zipfile!")
        return
    except binascii.Error:
        print("Invalid base64")

    if subprocess.run(["unzip", "-o", "-q", path, "-d", IMAGES_PATH]).returncode <= 1:
        print("Archive successfully uploaded and extracted")
    else:
        print("Error while extracting the archive")


def main():
    os.makedirs(IMAGES_PATH, exist_ok=True)

    print(BANNER)
    while True:
        option = menu()

        if option == 1:
            upload_image()
        elif option == 2:
            download_image()
        elif option == 3:
            delete_image()
        elif option == 4:
            upload_multiple_images()
        elif option == 5:
            print("bye.")
            break
        else:
            print("Invalid option!")


if __name__ == "__main__":
    main()
