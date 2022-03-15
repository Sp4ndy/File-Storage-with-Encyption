import mysql.connector

'''
mydb = mysql.connector.connect(
  host="localhost",
  user="root",
  password="",
  database="sec_file_storage"
)

mycursor = mydb.cursor()

sql = "INSERT INTO users (username, email, password) VALUES (%s, %s, %s)"
val = ("reece","reece.baptist@gmail.com","reece123")
mycursor.execute(sql, val)

mydb.commit()
'''
mydb = mysql.connector.connect(
  host="localhost",
  user="root",
  password="",
  database="sec_file_storage"
)

mycursor = mydb.cursor()

mycursor.execute("SELECT * FROM users WHERE username='"+"Reece"+"' AND password='"+"reece123"+"'")

myresult = mycursor.fetchall()

for x in myresult:
  print(x)