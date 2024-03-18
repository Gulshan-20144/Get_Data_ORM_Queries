import base64

def ImageEncode(image_field):
    # Read the image data
    # image_data = image_field.read()
    
    # Base64 encode the image data
    # encoded_data = base64.b64encode(image_data)
    
    # Decode the bytes to convert to a string (optional)
    # encoded_string = encoded_data.decode("utf-8")
    # print(encoded_string)
    with open("imageToSave.png", "wb") as fh:
        fh.write(image_field.read())
    # return encoded_string