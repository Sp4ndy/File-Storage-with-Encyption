import threading
import time

print("Serial version")
start_time = float(time.time())
def function1():
    i = 0
    while(i<10000): 
       i+=1
    return

function1()
function1()
end_time = float(time.time())

print(end_time-start_time)


class myThread (threading.Thread):
   def __init__(self, typee):
      threading.Thread.__init__(self)
      self.type = typee
   def run(self):
      # Get lock to synchronize threads      
        function1()
      # Free lock to release next thread
       
threads = []

print("Threads version")
start_time = time.time()
# Create new threads
thread1 = myThread(1)
thread2 = myThread(2)

# Start new Threads
thread1.start()
thread2.start()

# Add threads to thread list
threads.append(thread1)
threads.append(thread2)

end_time = time.time()
print(end_time-start_time)


'''
from flask import Flask, render_template, request
from Crypto import Random
from Crypto.Cipher import AES, Blowfish
from struct import pack
import os
import os.path
from os import listdir
from os.path import isfile, join
import time
import hashlib
import shutil
from zipfile import ZipFile

app = Flask(__name__)
def split_file(file_name):
    outputBase = file_name
    input = open(file_name,'rb').read()
    i = 1
    print(len(input))
    for lines in range(0, len(input), len(input)//2+1):
        outputData = input[lines: lines+(len(input)//2+1)]
        output = open(outputBase + "." + str(i),'wb')
        output.write(outputData)
        output.close()
        i += 1
    
filename =[]
def merge_file(file_name):
    with open("decrypted_"+file_name, 'wb') as fdst:
        filename.append(file_name+".1")
        filename.append(file_name+".2")
        for file in filename:
            with open(file,'rb') as frsc:
                shutil.copyfileobj(frsc,fdst,1024*1024*10)
    os.remove(file_name+".1")
    os.remove(file_name+".2")

class Encryptor:
    def __init__(self, key):
        self.key = key

    def pad(self, s):
        return s + b"\0" * (AES.block_size - len(s) % AES.block_size)

    def padBF(self, s):
        bs = Blowfish.block_size
        plen = bs - divmod(len(s),bs)[1]
        padding = [plen]*plen
        return s+pack('b'*plen,*padding)

    def Blowfishencrypt(self, message, key, key_size=256):
        message = self.padBF(message)
        iv = Random.new().read(Blowfish.block_size)
        cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
        return iv + cipher.encrypt(message)

    def AESencrypt(self, message, key, key_size=256):
        message = self.pad(message)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(message)

    def encrypt_file(self, file_name, type):
        with open(file_name, 'rb') as fo:
            plaintext = fo.read() 
        if(type == 1):
            enc = self.Blowfishencrypt(plaintext, self.key)
            with open(file_name+".blf", 'wb') as fo:
                fo.write(enc)
            os.remove(file_name)
        elif(type == 2):
            enc = self.AESencrypt(plaintext, self.key)
            with open(file_name+".aes", 'wb') as fo:
                fo.write(enc)
            os.remove(file_name)

    def Blowfishdecrypt(self, ciphertext, key):
        iv = ciphertext[:Blowfish.block_size]
        cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
        plaintext = cipher.decrypt(ciphertext[Blowfish.block_size:])
        return plaintext.rstrip(b"\0")             

    def AESdecrypt(self, ciphertext, key):
        iv = ciphertext[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(ciphertext[AES.block_size:])
        return plaintext.rstrip(b"\0")

    def decrypt_file(self, file_name, type):
        with open(file_name, 'rb') as fo:
            ciphertext = fo.read()
        if(type == 1):
            dec = self.Blowfishdecrypt(ciphertext, self.key)
            with open(file_name[:-4], 'wb') as fo:
                fo.write(dec)
            os.remove(file_name)   
        elif(type == 2):
            dec = self.AESdecrypt(ciphertext, self.key)
            with open(file_name[:-4], 'wb') as fo:
                fo.write(dec)
            os.remove(file_name)   

password = "1234"
key = hashlib.md5(password.encode()).digest()
fil = 'text.txt'
dec = Encryptor(key)
with ZipFile(str(fil)+'.zip', 'r') as zipObj:
   zipObj.extractall()
dec.decrypt_file(str(fil)+".1.blf",1)
dec.decrypt_file(str(fil)+".2.aes",2)
merge_file(str(fil))

'''


'''
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA512, SHA384, SHA256, SHA, MD5
from Crypto import Random
from base64 import b64encode, b64decode
hash = "SHA-256"


def newkeys(keysize):
    random_generator = Random.new().read
    key = RSA.generate(keysize, random_generator)
    private, public = key, key.publickey()
    return public, private

def importKey(externKey):
   return RSA.importKey(externKey)

def getpublickey(priv_key):
   return priv_key.publickey()

def encrypt(message, pub_key):
   cipher = PKCS1_OAEP.new(pub_key)
   return cipher.encrypt(message)

def decrypt(ciphertext, priv_key):
   cipher = PKCS1_OAEP.new(priv_key)
   return cipher.decrypt(ciphertext)

def sign(message, priv_key, hashAlg = "SHA-256"):
   global hash
   hash = hashAlg
   signer = PKCS1_v1_5.new(priv_key)
   
   if (hash == "SHA-512"):
      digest = SHA512.new()
   elif (hash == "SHA-384"):
      digest = SHA384.new()
   elif (hash == "SHA-256"):
      digest = SHA256.new()
   elif (hash == "SHA-1"):
      digest = SHA.new()
   else:
      digest = MD5.new()
   digest.update(message)
   return signer.sign(digest)

def verify(message, signature, pub_key):
   signer = PKCS1_v1_5.new(pub_key)
   if (hash == "SHA-512"):
      digest = SHA512.new()
   elif (hash == "SHA-384"):
      digest = SHA384.new()
   elif (hash == "SHA-256"):
      digest = SHA256.new()
   elif (hash == "SHA-1"):
      digest = SHA.new()
   else:
      digest = MD5.new()
   digest.update(message)
   return signer.verify(digest, signature)

pub, priv = newkeys(1024)
a = sign('1234'.encode("utf8"),priv)
aa = pub.exportKey(format='OpenSSH', passphrase=None, pkcs=1, protection=None, randfunc=None)
print(type(aa))
print(aa)
print(verify('1234'.encode("utf8"),a,importKey(aa)))

aa = str(aa)
print(aa)
print(type(aa))
aa = str.encode(aa[2:len(aa)-1])
print(aa)
print(verify('1234'.encode("utf8"),a,importKey(aa)))

'''
'''
import smtplib, ssl

port = 587

sender, password = "isaa.project.vit1@gmail.com","ISAAproject123"

recieve = sender

subject = 'Grab dinner?'
body = 'Okay?'

msg = f'Subject: {subject}\n\n{body}'

with smtplib.SMTP('smtp.gmail.com',port) as server:
    server.ehlo()
    server.starttls()
    server.ehlo()
    server.login(sender, password)
    server.sendmail(sender, recieve, msg)
print("EMail sent")

'''

