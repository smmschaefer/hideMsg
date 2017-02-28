# hideMsg
Hides a secret message inside of an image.  Using PPM images this program is split into two.  One side encrpts a message and embeds it into an image.  It embedsthe message into the image at every LSB. Embed a total of up to three bits per pixel by embedding up to one bit in each of the LSB’s of the red, green, and blue channels.

The next program extracts and decrypts the message.  

Encryption using PBKDF2 with SHA1 

# To encrypt and embed

 encemb -c <cover filename> -m <message filename> -s <stego filename> -p <password>

# To decrypt and extract

extdec -s <stego filename> -m <message filename> -p <password>
