from flask import *
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, Blowfish, PKCS1_OAEP
from Crypto.Hash import SHA512, SHA384, SHA256, SHA, MD5
from Crypto.Signature import PKCS1_v1_5
from base64 import b64encode, b64decode
from struct import pack
import os
import os.path
import time
import hashlib
import shutil
from zipfile import ZipFile
import boto3
from botocore.client import Config
import mysql.connector
import smtplib
import sys
import re
import threading

ii=0
kk=0
#-------------------------------------------------------------------------
#ENCRYTION
#SERIAL CODE:
def Blowfishencrypt(message, key, key_size=256):
    message = padBF(message)
    iv = Random.new().read(Blowfish.block_size)
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    return iv + cipher.encrypt(message)

def AESencrypt(message, key, key_size=256):
    message = pad(message)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(message)

def pad(s):
    return s + b"\0" * (AES.block_size - len(s) % AES.block_size)

def padBF(s):
    bs = Blowfish.block_size
    plen = bs - divmod(len(s),bs)[1]
    padding = [plen]*plen
    return s+pack('b'*plen,*padding)
    
k=[]
def encrypt(fil):
    password = '1234'
    key = hashlib.md5(password.encode()).digest()
    
    with open(fil,'rb') as fo:
        plaintext = fo.read()    
    s = time.time()
    enc = Blowfishencrypt(plaintext,key)
    with open(fil+".enc1",'wb') as fo:
        fo.write(enc)
    kk = (time.time()-s)
    return kk

#-----------------------------------------------------
#PARALLEL CODE
def Blowfishencrypt(message, key, key_size=256):
    message = padBF(message)
    iv = Random.new().read(Blowfish.block_size)
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    return iv + cipher.encrypt(message)

def AESencrypt(message, key, key_size=256):
    message = pad(message)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(message)

def pad(s):
    return s + b"\0" * (AES.block_size - len(s) % AES.block_size)

def padBF(s):
    bs = Blowfish.block_size
    plen = bs - divmod(len(s),bs)[1]
    padding = [plen]*plen
    return s+pack('b'*plen,*padding)

class myThread (threading.Thread):
   def __init__(self, count,filename, plaintext, key):
      threading.Thread.__init__(self) 
      self.count = count
      self.filename = filename     
      self.plaintext = plaintext
      self.key = key
   def run(self):
      # Get lock to synchronize threads
      threadLock.acquire()
      enc = Blowfishencrypt(self.plaintext,self.key)
      #enc = AESencrypt(enc,self.key)
      with open(self.filename+".enc2",'wb') as fo:
        print(self.count)
        fo.write(enc)
      # Free lock to release next thread
      threadLock.release()


threadLock = threading.Lock()
threads = []
def pencrypt(fil):
    password = '1234'
    key = hashlib.md5(password.encode()).digest()
    

    with open(fil,'rb') as fo:
        plaintext = fo.read()
    
    # Create new threads
    thread1 = myThread(1, fil, plaintext[:len(plaintext)//8],key)
    thread2 = myThread(2, fil, plaintext[len(plaintext)//8:len(plaintext)//4],key)
    thread3 = myThread(3, fil, plaintext[len(plaintext)//4:3*(len(plaintext)//8)],key)
    thread4 = myThread(4, fil, plaintext[3*(len(plaintext)//8):len(plaintext)//2],key)
    thread5 = myThread(5, fil, plaintext[len(plaintext)//2:5*(len(plaintext)//8)],key)
    thread6 = myThread(6, fil, plaintext[5*(len(plaintext)//8):3*(len(plaintext)//4)],key)
    thread7 = myThread(7, fil, plaintext[3*(len(plaintext)//4):7*(len(plaintext)//8)],key)
    thread8 = myThread(8, fil, plaintext[7*(len(plaintext)//8):],key)

    # Start new Threads
    s = time.time()
    thread1.start()
    thread2.start()
    thread3.start()
    thread4.start()
    thread5.start()
    thread6.start()
    thread7.start()
    thread8.start()
    # Add threads to thread list
    threads.append(thread1)
    threads.append(thread2)
    threads.append(thread3)
    threads.append(thread4)
    threads.append(thread5)
    threads.append(thread6)
    threads.append(thread7)
    threads.append(thread8)

    # Wait for all threads to complete
    for t in threads:
        t.join()
    ii = (time.time()-s)    
    return ii

fil = ['image1.jpg','image2.jpg','video1.mp4','video2.mp4','video3.mov']
print(encrypt(fil[2]) > pencrypt(fil[2]))


#-----------------------------------------------------------
#Serial Decrypt
def Blowfishdecrypt(ciphertext, key):
    iv = ciphertext[:Blowfish.block_size]
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext[Blowfish.block_size:])
    return plaintext.rstrip(b"\0")             

def AESdecrypt(ciphertext, key):
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext[AES.block_size:])
    return plaintext.rstrip(b"\0")

def decrypt(fil):
    password = '1234'
    key = hashlib.md5(password.encode()).digest()
    with open(fil+".enc1",'rb') as fo:
        ciphertext = fo.read()    
    s = time.time()
    enc = Blowfishdecrypt(ciphertext,key)
    os.remove(fil+".enc1")
    with open("decs_"+fil,'wb') as fo:
        fo.write(enc)
    kk = (time.time()-s)
    return kk

print(decrypt(fil[2]))
