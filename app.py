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
import time, threading
import hashlib
import shutil
from zipfile import ZipFile
import boto3
from botocore.client import Config
import mysql.connector
import smtplib
import sys
import re
import random

ACCESS_KEY_ID = 'AKIA2WPOSZGFYTG5O5UX'
ACCESS_SECRET_KEY = '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'
BUCKET_NAME = 'isaa-project'

app = Flask(__name__)
app.secret_key = "abc"

def split_file(file_name):
    outputBase = file_name
    input = open(file_name,'rb').read()
    i = 1
    for lines in range(0, len(input), len(input)//2+1):
        outputData = input[lines: lines+(len(input)//2+1)]
        output = open(outputBase + "." + str(i),'wb')
        output.write(outputData)
        output.close()
        i += 1
    
filename =[]

def merge_file(file_name):
    time.sleep(3)
    with open("decrypted_"+file_name, 'wb') as fdst:
        filename.append(file_name+".1")
        filename.append(file_name+".2")
        for file in filename:
            with open(file,'rb') as frsc:
                shutil.copyfileobj(frsc,fdst,1024*1024*10)
    os.remove(file_name+".1")
    os.remove(file_name+".2")
    os.remove(file_name+".zip")

def upload_cloud(file_name):
    data = open(file_name, 'rb')
        # S3 Connect
    s3 = boto3.resource(
        's3',
        aws_access_key_id=ACCESS_KEY_ID,
        aws_secret_access_key=ACCESS_SECRET_KEY,
        config=Config(signature_version='s3v4')
            )
    # Image Uploaded
    s3.Bucket(BUCKET_NAME).put_object(Key=file_name, Body=data)
    return

def list_cloud():
    # S3 Connect
    s3 = boto3.resource(
        's3',
        aws_access_key_id=ACCESS_KEY_ID,
        aws_secret_access_key=ACCESS_SECRET_KEY,
        config=Config(signature_version='s3v4')
    )
    return s3.Bucket(BUCKET_NAME).objects.all()

def download_cloud(file_name):
    FILE_NAME = file_name
    # S3 Connect
    s3 = boto3.resource(
        's3',
        aws_access_key_id=ACCESS_KEY_ID,
        aws_secret_access_key=ACCESS_SECRET_KEY,
        config=Config(signature_version='s3v4')
    )
    # Image download
    s3.Bucket(BUCKET_NAME).download_file(FILE_NAME, 'C:/xampp/htdocs/ISAA/'+FILE_NAME); # Change the second part
    # This is where you want to download it too.
    return 

mydb = mysql.connector.connect(
  host="localhost",
  user="root",
  password="",
  database="sec_file_storage"
)
mycursor = mydb.cursor()

def loginvalidation(username, password):
    sql = "SELECT * FROM users WHERE username=%s AND password=%s"
    val = (username, password)
    mycursor.execute(sql, val)
    myresult = mycursor.fetchall()
    if(len(myresult) == 1):
        if(username == myresult[0][0] and password == myresult[0][2]):
            return 1
        else:
            return 0
    else:
        return 0

def check_password(password):
    sql = "SELECT * FROM files WHERE filename=%s"
    val = (session['file'],)
    mycursor.execute(sql, val)
    myresult = mycursor.fetchall()
    if (myresult[0][1] == password):
        return 1
    else:
        return 0

def upload_key(file_name, key):
    sql = "INSERT INTO files(filename, secretkey) VALUES(%s, %s)"
    val = (file_name, key)
    mycursor.execute(sql, val)
    mydb.commit()

def get_key(file_name):
    sql = "SELECT * FROM files WHERE filename=%s"
    val = (file_name,)
    mycursor.execute(sql, val)
    myresult = mycursor.fetchall()
    return myresult

def email(publickey):
    sql = "SELECT * FROM users WHERE username=%s"
    val = (session['username'],)
    mycursor.execute(sql, val)
    port = 587
    sender, password = "isaa.project.vit1@gmail.com","ISAAproject123"
    recieve = mycursor.fetchall()[0][1]
    subject = 'ISAA Project - OTP for Download: '
    body = publickey
    msg = f'Subject: {subject}\n\n{body}'
    with smtplib.SMTP('smtp.gmail.com',port) as server:
        server.ehlo()
        server.starttls()
        server.ehlo()
        server.login(sender, password)
        server.sendmail(sender, recieve, msg)

def emailotp(ranno):
    sql = "SELECT * FROM users WHERE username=%s"
    val = (session['checkUN'],)
    mycursor.execute(sql, val)
    port = 587
    sender, password = "isaa.project.vit1@gmail.com","ISAAproject123"
    recieve = mycursor.fetchall()[0][1]
    subject = 'ISAA Project - OTP for Login: '
    body = ranno
    msg = f'Subject: {subject}\n\n{body}'
    with smtplib.SMTP('smtp.gmail.com',port) as server:
        server.ehlo()
        server.starttls()
        server.ehlo()
        server.login(sender, password)
        server.sendmail(sender, recieve, msg)

def add_user(username, email, password):
    sql = "INSERT INTO users(username, email, password) VALUES(%s, %s, %s)"
    val = (username, email, password)
    mycursor.execute(sql,val)
    mydb.commit()
    return 

hash="SHA-256"       
class KeyEncryptor:
    def newkeys(self, keysize):
        random_generator = Random.new().read
        key = RSA.generate(keysize, random_generator)
        private, public = key, key.publickey()
        return public, private

    def importKey(self, externKey):
        return RSA.importKey(externKey)

    def getpublickey(self, priv_key):
        return priv_key.publickey()

    def encrypt(self, message, pub_key):
        cipher = PKCS1_OAEP.new(pub_key)
        return cipher.encrypt(message)

    def sign(self, message, priv_key, hashAlg = "SHA-256"):
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

    def verify(self, message, signature, pub_key):
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

def pAESencrypt(filename, key, zipObj, key_size=256):
    with open(filename,'rb') as fo:
        message = fo.read()
    message = pad(message)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    with open(filename,'wb') as fo:
        fo.write(iv + cipher.encrypt(message))
    zipObj.write(filename)
    os.remove(filename)

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

class myThread (threading.Thread):
   def __init__(self, filename, plaintext, key, zipObj):
      threading.Thread.__init__(self) 
      self.filename = filename     
      self.plaintext = plaintext
      self.key = key
      self.zipObj = zipObj
   def run(self):
      # Get lock to synchronize threads
      threadLock.acquire()
      pAESencrypt(self.plaintext,self.key,self.zipObj)
      # Free lock to release next thread
      threadLock.release()


threadLock = threading.Lock()
     

def checkUsername(username):
    sql = "SELECT * FROM users WHERE username=%s"
    val = (username,)
    mycursor.execute(sql,val)
    myresult = mycursor.fetchall()
    if(len(myresult) > 0):
        return 0
    else:
        if (re.search("[a-z]", username) or re.search("[A-Z]", username) or re.search("[0-9]", username)):
            return 1
        else:
            return 0

def checkEmail(email):
    if(re.search('^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$',email)):
        sql = "SELECT * FROM users WHERE email=%s"
        val = (email,)
        mycursor.execute(sql,val)
        myresult = mycursor.fetchall()
        if(len(myresult) > 0):
            return 0
        else:
            return 1
    else:
        return 0

def checkPassword(password):
    if(len(password) > 10):
        if re.search("[a-z]", password):
            if re.search("[A-Z]", password):
                if re.search("[0-9]", password):
                    return 1
                else:
                    return 0
            else:
                return 0
        else:
            return 0
    else:
        return 0



@app.route('/')
def index():
    session['downloaded'] = ''
    if 'username' not in session:
        button = "<a href='/login'><button class='btn btn-secondary my-2 my-sm-0'> Log In </button></a><a href='/register'><button class='btn btn-secondary my-2 ml-2 my-sm-0'>Register</button></a>"
    else:
        button = "<a href='/logout'><button class='btn btn-secondary my-2 my-sm-0'> Logged in as "+session['username']+" </button></a>"
    return render_template('index.html', button = button)

@app.route('/login')
def login_html():
    if 'username' in session:
        return redirect(url_for('index'))
    return render_template('login.html',error="closee()")

@app.route('/login',methods=['POST'])
def login_post():
    username = request.form['username']
    password = request.form['password']
    if(loginvalidation(username, password)):
        #return redirect(url_for('index'))
        session['otp'] = str(random.randint(1000,9999))
        session['checkUN'] = username
        emailotp(session['otp'])
        return redirect(url_for('otp_html'))
    else:
        return render_template('login.html',error="openn()")

@app.route('/otp')
def otp_html():
    return render_template('otp.html',error="closee()")

@app.route('/otp',methods=['POST'])
def otp_post():
    otp = request.form['otp']
    if(session['otp'] == otp):
        session['username'] = session['checkUN']
        return redirect(url_for('index'))
    else:
        return render_template('otp.html',error="openn()")

@app.route('/encrypt')
def encrypt_html():
    if 'username' not in session:
        return redirect(url_for('login_html'))
    else:
        return render_template('encrypt.html',
            k="closee()",
            username = session['username']
            )

@app.route('/decrypt')
def decrypt_html():
    if 'username' not in session:
        return redirect(url_for('login_html'))
    else:
        table = ""
        i = 1
        for obj in list_cloud():
            table += "<tr><td>"+str(i)+"</td><td>"+obj.key[:-4]+"</td>"
            table += "<td><form method='POST'><button type='submit' name='download' class='btn btn-secondary' value='"+obj.key+"'>Download</button></form></td></tr>"
            i += 1
        
        k=""
        if 'downloaded' in session:
            if(session['downloaded']):
                k = "openn()"
            else:
                k = "closee()"
            session.pop('downloaded', None)
        return render_template('decrypt.html',
            k=k,
            username = session['username'],
            table = table)            

@app.route('/encrypt',methods=['POST'])
def encrypt_post():
    password = request.form['key']
    key = hashlib.md5(password.encode()).digest()
    fil = request.form['file']
    file_number = 1
    zipObj = ZipFile(str(fil)+'.zip', 'w')
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
    thread1 = myThread(fil, "1_"+fil,key,zipObj)
    thread2 = myThread(fil, "2_"+fil,key,zipObj)
    thread3 = myThread(fil, "3_"+fil,key,zipObj)
    thread4 = myThread(fil, "4_"+fil,key,zipObj)
    thread5 = myThread(fil, "5_"+fil,key,zipObj)
    thread6 = myThread(fil, "6_"+fil,key,zipObj)
    thread7 = myThread(fil, "7_"+fil,key,zipObj)
    thread8 = myThread(fil, "8_"+fil,key,zipObj)


    thread1.start()
    thread2.start()
    thread3.start()
    thread4.start()
    thread5.start()
    thread6.start()
    thread7.start()
    thread8.start()
    
    threads = []
    threads.append(thread1)
    threads.append(thread2)
    threads.append(thread3)
    threads.append(thread4)
    threads.append(thread5)
    threads.append(thread6)
    threads.append(thread7)
    threads.append(thread8)

    for t in threads:
        t.join()
    
    zipObj.close()
    upload_cloud(str(fil)+".zip")
    os.remove(str(fil)+".zip")
    upload_key(str(fil),password)
    return render_template('encrypt.html',k="openn()",username = session['username'])

@app.route('/decrypt', methods=['POST'])
def decrypt_post():
    file_name = request.form['download']
    session['file'] = file_name[:-4]
    key = get_key(file_name[:-4])[0][1]
    kenc = KeyEncryptor()
    pub, priv = kenc.newkeys(1024)
    signed = kenc.sign(key.encode("utf8"), priv)
    session['signed'] = signed
    email(pub.exportKey(format='OpenSSH', passphrase=None, pkcs=1, protection=None, randfunc=None))
    return redirect(url_for('download_html'))

@app.route('/download')
def download_html():
    if 'username' not in session:
        return redirect(url_for('login_html'))
    else:
        file_name = session['file']
        return render_template('download.html',file_name = file_name, k="closee()")

@app.route('/download',methods=['POST'])
def download_post():
    print("Hiiiii")
    password = request.form['key']
    MFA = request.form['MFAkey']
    if(check_password(password)):        
        kenc = KeyEncryptor()
        try:
            MFA = str.encode(MFA[2:len(MFA)-1])
            pub = kenc.importKey(MFA)
        except ValueError:
            return render_template('download.html',file_name = 2,k="openn()")
        if(kenc.verify(password.encode("utf8"), session['signed'],pub)):
            download_cloud(session['file']+".zip")
            key = hashlib.md5(password.encode()).digest()
            #dec = Encryptor(key)
            with ZipFile(session['file']+'.zip', 'r') as zipObj:
                zipObj.extractall()
            for i in range(1,9):
                with open(str(i)+"_"+session['file'],'rb') as fo:
                    ct = fo.read()
                ct = AESdecrypt(ct,key)
                with open(str(i)+"_"+session['file'],'wb') as fo:
                    fo.write(ct)
            filename = []
            for i in range(1,9):
                filename.append(str(i)+"_"+session['file'])
            with open("decrypted_"+session['file'], 'wb') as fdst:
                for file in filename:
                    with open(file,'rb') as frsc:
                        shutil.copyfileobj(frsc,fdst,1024*1024*20)
            for i in range(1,9):
                os.remove(str(i)+"_"+session['file'])
            os.remove(session['file']+".zip")
            session['downloaded'] = 1
            session.pop('file', None)
            session.pop('signed', None)
            return redirect(url_for('decrypt_html'))
        else:
            return render_template('download.html',file_name = session['file'],k="openn()")
    else:
        return render_template('download.html',file_name = session['file'],k="openn()")

@app.route('/register')
def register_html():
    if 'username' in session:
        return redirect(url_for('index'))
    return render_template('register.html',k="closee()",color="",alert="",text="")

@app.route('/register',methods=['POST'])
def register_post():
    username = request.form['username']
    email = request.form['email']
    password = request.form['password']
    if(checkUsername(username)):
        if(checkEmail(email)):
            if(checkPassword(password)):
                add_user(username, email, password)
                return render_template('register.html',k="openn()",color="success",alert="Success!",text="You are now registered")
            else:
                return render_template('register.html',k="openn()",color="danger",alert="Alert!",text="Not a valid password format")
        else:
            return render_template('register.html',k="openn()",color="danger",alert="Alert!",text="Email address is taken or inavlid email entry")
    else:
        return render_template('register.html',k="openn()",color="danger",alert="Alert!",text="Username has been taken or invalid username entry.")


@app.route('/logout')
def logout_html():
    session.pop('username', None)  
    return redirect(url_for('login_html'))

if __name__ == '__main__':
    app.run(debug=True)
