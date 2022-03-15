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

def AESdecrypt(ciphertext, key):
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext[AES.block_size:])
    return plaintext.rstrip(b"\0")  

def Blowfishdecrypt(ciphertext, key):
    iv = ciphertext[:Blowfish.block_size]
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext[Blowfish.block_size:])
    return plaintext.rstrip(b"\0") 
    

def encrypt(fil):
    password = '1234'
    key = hashlib.md5(password.encode()).digest()
     
    s = time.time()
    with open(fil,'rb') as fo:
        plaintext = fo.read()   
    enc = Blowfishencrypt(plaintext,key)
    with open(fil+".enc1",'wb') as fo:
        fo.write(enc)
    kk = (time.time()-s)
    dec = Blowfishdecrypt(enc,key)
    os.remove(fil+".enc1")
    with open("serial_"+fil,'wb') as fo:
        fo.write(dec)
    return kk

#-----------------------------------------------------
#PARALLEL CODE
def pBlowfishencrypt(filename, key, key_size=256):
    with open(filename,'rb') as fo:
        message = fo.read()
    message = padBF(message)
    iv = Random.new().read(Blowfish.block_size)
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    with open(filename,'wb') as fo:
        fo.write(iv + cipher.encrypt(message))

def pAESencrypt(filename, key, key_size=256):
    with open(filename,'rb') as fo:
        message = fo.read()
    message = pad(message)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    with open(filename,'wb') as fo:
        fo.write(iv + cipher.encrypt(message))

def pad(s):
    return s + b"\0" * (AES.block_size - len(s) % AES.block_size)

def padBF(s):
    bs = Blowfish.block_size
    plen = bs - divmod(len(s),bs)[1]
    padding = [plen]*plen
    return s+pack('b'*plen,*padding)  

class myThread (threading.Thread):
   def __init__(self, filename, plaintext, key):
      threading.Thread.__init__(self) 
      self.filename = filename     
      self.plaintext = plaintext
      self.key = key
   def run(self):
      # Get lock to synchronize threads
      threadLock.acquire()
      pAESencrypt(self.plaintext,self.key)
      # Free lock to release next thread
      threadLock.release()


threadLock = threading.Lock()
threads = []
def pencrypt(fil):
    password = '1234'
    key = hashlib.md5(password.encode()).digest()
    
    file_number = 1
    with open(fil,'rb') as f:
        pt = f.read()
    CHUNK_SIZE = len(pt)//8+1
    with open(fil,'rb') as fi:
        chunk = fi.read(CHUNK_SIZE)
        while chunk:
            with open(str(file_number)+"_"+fil,'wb') as chunk_file:
                chunk_file.write(chunk)
            file_number += 1
            chunk = fi.read(CHUNK_SIZE)      
    
    # Create new threads
    thread1 = myThread(fil, "1_"+fil,key)
    thread2 = myThread(fil, "2_"+fil,key)
    thread3 = myThread(fil, "3_"+fil,key)
    thread4 = myThread(fil, "4_"+fil,key)
    thread5 = myThread(fil, "5_"+fil,key)
    thread6 = myThread(fil, "6_"+fil,key)
    thread7 = myThread(fil, "7_"+fil,key)
    thread8 = myThread(fil, "8_"+fil,key)

    # Start new Threads

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
    
    s = time.time()
    # Wait for all threads to complete
    for t in threads:
        t.join()
    ii = (time.time()-s)    
    return ii

fil='imagetemp.jpg'

print(encrypt(fil) , pencrypt(fil))


#-----------------------
#DECRYPT

def AESdecrypt(ciphertext, key):
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext[AES.block_size:])
    return plaintext.rstrip(b"\0")  

def decrypt(fil):
    password = '1234'
    key = hashlib.md5(password.encode()).digest()
    for i in range(1,9):
        with open(str(i)+"_"+fil,'rb') as fo:
            ct = fo.read()
        ct = AESdecrypt(ct,key)
        with open(str(i)+"_"+fil,'wb') as fo:
            fo.write(ct)
    filename = []
    for i in range(1,9):
        filename.append(str(i)+"_"+fil)
    with open("decrypted_"+fil, 'wb') as fdst:
        for file in filename:
            with open(file,'rb') as frsc:
                shutil.copyfileobj(frsc,fdst,1024*1024*20)
    for i in range(1,9):
        os.remove(str(i)+"_"+fil)

decrypt(fil)


