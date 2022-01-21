# -*- coding: utf-8 -*-
"""
Created on Thu Sep 30 13:33:09 2021

@author: Johnathan Turner
"""
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


master_password = input('What is the master password?: ')
#salt = os.urandom(16)
def generate_key_derivation(salt, master_password):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000, #320000 iterations recommended by Django as of 01/2021
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    return key

key = generate_key_derivation(salt, master_password)
'''
Make sure to uncomment salt and import os in order to create a new master password.
WARNING: You will not be able to recover your data if you do this.
'''
fer = Fernet(key) #Reference fer for encrypting and decrypting info from your file.

#The main menu
def siteMenu():
    print('Your options are: ')
    print('0. Quit')
    print('1. Add')
    print('2. Change')
    print('3. Remove')
    print('4. View all')
    inp = input('Please give and number from 0-4: ')
    try:
        inp = int(inp)
        if inp > 4 or inp < 0:
            print('Error: Please enter a number only from 0-4!')
    except:
        print('Error: Please enter a number')
    if inp == 0:
        return False
    elif inp == 1:  #Add new entry
        new_site = promt()
        add(new_site)
        siteMenu()
    elif inp == 2:  #Change one part of an entry, giving only the website
        change_site = promt()
        change(change_site)
        siteMenu()
    elif inp == 3:  #Remove an entry with only the website
        remove_site = promt()
        remove(remove_site)
        siteMenu()
    elif inp == 4:  #View all decrypted entries
        read()
        siteMenu()

def read():  #The function called to view all decrypted entries
    with open('passwords.txt', 'r') as f:
        d = f.readlines()
        number_of_entries = 0
        for line in d:
            if line.rstrip():
                number_of_entries += 1
                site, username, password = line.split('|')
                print('Website: ' + site + '| Username: ' + fer.decrypt(username.encode()).decode() + '| Password: ' + fer.decrypt(password.encode()).decode())
        print('There are ' + str(number_of_entries) + ' entries in the database')
        extraSpace()

def remove(remove_site, change=False):  #The function called to remove a specified entry, given a website name
    with open('passwords.txt', 'r') as f:
        d = f.readlines()  #Read the entire file
    with open('passwords.txt', 'w') as f:
        pull = ''
        number_of_entries = 0
        for line in d:
            if line.rstrip():
                site, username, password = line.split('|')
                if site != remove_site:
                    f.write(site + '|' + username + '|' + password)
                else:
                    pull = site  #Checking there is actually an entry
                    if change and number_of_entries == 1:
                        f.write(site + '|' + username + '|' + password)
                        continue
                    if checking(site, username, password):  #Checking if they actually want to remove the entry
                        number_of_entries += 1
                    else:
                        f.write(site + '|' + username + '|' + password)

        print('Removed ' + str(number_of_entries) + ' entries from the database')
        if not pull:  #If website not found, produce and error
            print('Error: Website not found in database!')
            extraSpace()
            return
        extraSpace()



def change(change_site):  #The function called to change a specified entry, given a website name
    with open('passwords.txt', 'r') as f:
        d = f.readlines()
        pull = ''
        for line in d:
            if line.rstrip():
                site, username, password = line.split('|')
                if site != change_site:
                    continue
                else:
                    pull = site
                    '''
                    ^Checking there is actually an entry
                    If there are multiples of the same website, it will ask about all of them.
                    '''
                usernameDec = fer.decrypt(username.encode()).decode()
                passwordDec = fer.decrypt(password.encode()).decode()
                print('What would you like to change?')
                print('0. No change')
                print('1. Website: ' + site)
                print('2. Username: ' + usernameDec)
                print('3. Password: ' + passwordDec)
                inp = input('Please give and number from 0-3: ')
                try:
                    inp = int(inp)
                    if inp > 3 or inp < 0:
                        print('Error: Please enter a number only from 0-3!')
                except:
                    print('Error: Please enter a corresponding number')
                if inp == 0:
                    continue
                elif inp == 1:
                    changling(site, username, password, inp)
                elif inp == 2:
                    changling(site, username, password, inp)
                elif inp == 3:
                    changling(site, username, password, inp)
        extraSpace()
        if not pull:
            print('Error: Website not found in database!')
            extraSpace()
            return

def changling(site, username, password, choice):
    add_part = input('Please enter your new one: ')
    if int(choice) == 1:
        part = site
        addFixed(part, username, password)
    elif int(choice) == 2:
        part = username
        addFixed(site, fer.encrypt(add_part.encode()).decode(), password)
    elif int(choice) == 3:
        part = password
        addFixed(site, username, fer.encrypt(add_part.encode()).decode())
    remove(site, True)
    print(fer.decrypt(part.encode()).decode() +' successfully changed to '+ add_part)





def add(site):  #The function called to add an entry, given a website name
    username = input("Please enter the username you would like to add: ")
    password = input("Please enter the password associated with that username: ")
    with open('passwords.txt', 'a') as f:
        f.write(site + '|' + fer.encrypt(username.encode()).decode() + '|' + fer.encrypt(password.encode()).decode() + '\n')
        extraSpace()

def addFixed(site, username, password):  #The function called to add an entry without prompting the user
    with open('passwords.txt', 'a') as f:
        f.write(site + '|' + username + '|' + password + '\n')

def promt():  #Allows someone to go backwards out of a submenu or continue
    print('0. Go back')
    some_site = input('Enter the name of the website you would like to alter: ')
    if str(some_site)=='0':
        siteMenu()
    return some_site

def checking(site, username, password):  #In remove(), checks if the website is intended to be removed
    print('\nWebsite: ' + site + '| Username: ' + fer.decrypt(username.encode()).decode() + '| Password: ' + fer.decrypt(password.encode()).decode())
    inp = input('Are you sure you would like to remove this entry? (Y/N): ')
    inp = inp.lower()
    if inp == 'y' or inp == 'yes':
        return True
    if inp == 'n' or inp == 'no':
        return False
    else:
        print('Please enter a valid response: \"Y\" or \"N\" \n')
        checking(site, username, password)
        return

def extraSpace():  #A nive UI separator
    print('---------------------------------------------------------------------\n')

while True:  #The main executable loop. Only breaks if the user enters '0' in the siteMenu()
    if not siteMenu():
        break
