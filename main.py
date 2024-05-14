import sqlite3
import secrets
import string
# import cryptography

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import webbrowser
import clipboard
import re
import time
import pyaes    # for AES
# https://stackoverflow.com/questions/25261647/python-aes-encryption-without-extra-module

db_connection = sqlite3.connect("passwords_DB.db")


def database_and_tables():
    print("Alhamdulillah! DB created")

    db_connection.execute("""CREATE TABLE IF NOT EXISTS master(     
                 username VARCHAR(30) PRIMARY KEY,
                 verification_key TEXT
    );
    """)

    db_connection.execute("""CREATE TABLE IF NOT EXISTS credentials(
                 master_username VARCHAR(30) NOT NULL,
                 username_or_email VARCHAR(30) NOT NULL,  
                 encrypted_pass TEXT,  
                 website TEXT,  
                 website_URL TEXT,
                 CONSTRAINT pk_constraint PRIMARY KEY (master_username, website),
                 FOREIGN KEY (master_username) REFERENCES master(username)         
    );
    """)

    db_connection.close()


def program_menu(mt_username, enc_dec_key):
    print("""\nEnter '1' to Add your Credentials
Enter '2' to Delete your Credentials
Enter '3' to Update your Credentials
Enter '4' to View your Credentials
Enter '5' to Open Website Login Page
Enter '6' to Generate Password
Enter '7' to Analyze Password Strength
Enter '8' to exit
""")
    choice = input("Enter your Choice : ")
    if choice == '1':
        add_credentials(mt_username, enc_dec_key)
    elif choice == '2':
        delete_credentials(mt_username, enc_dec_key)
    elif choice == '3':
        update_credentials(mt_username, enc_dec_key)
    elif choice == '4':
        view_credentials(mt_username, enc_dec_key)
    elif choice == '5':
        website_login_page(mt_username, enc_dec_key)
    elif choice == '6':
        password_generator(mt_username, enc_dec_key)
    elif choice == '7':
        analyze_password_strength(mt_username, enc_dec_key, "")
    elif choice == '8':
        return
    else:
        print("Invalid Input!")
        program_menu(mt_username, enc_dec_key)


def analyze_password_strength(mt_username, enc_dec_key, password_to_check):
    flag_for_program_menu = False

    if len(password_to_check) == 0:
        flag_for_program_menu = True
        password_to_check = input("Enter the password to analyze the strength : ")
    
    standard_length = 12; length_flag = True
    length_check = len(password_to_check)
    if length_check < standard_length:
        length_flag = False

    lowercase_flag = bool(re.search(r'[a-z]', password_to_check))
    uppercase_flag = bool(re.search(r'[A-Z]', password_to_check))
    digit_flag = bool(re.search(r'[0-9]', password_to_check))
    symbol_flag = bool(re.search(r'[@_!$%^&*?/\|()<>}{~:#]', password_to_check))

    pass_strength = "Weak"
    if length_flag and any([length_flag, lowercase_flag, uppercase_flag, digit_flag, symbol_flag]):
        pass_strength = "Medium"
    if all([length_flag, lowercase_flag, uppercase_flag, digit_flag, symbol_flag]):
        pass_strength = "Strong"

    print(f"\nPassword is {pass_strength}!")

    if flag_for_program_menu:
        time.sleep(1)
        menu = input("\nEnter 'Y' if you want to go to Program Menu \nEnter Any Key to exit: ").lower()
        if menu == 'y':
            program_menu(mt_username, enc_dec_key)

    if pass_strength == "Medium" or pass_strength == "Strong":
        return True
    
    return False


def password_generator(mt_username, enc_dec_key):
    characters = ""

    length = int(input("Enter the length of your password : "))

    low = input("Include lowercase letters in your password (Y/N)? ").lower()
    if low == 'y':
        characters += string.ascii_lowercase
    upper = input("Include uppercase letters in your password (Y/N)? ").lower()
    if upper == 'y':
        characters += string.ascii_uppercase
    dig = input("Include digits in your password (Y/N)? ").lower()
    if dig == 'y':
        characters += string.digits
    sym = input("Include symbols in your password (Y/N)? ").lower()
    if sym == 'y':
        characters += string.punctuation
    
    generated_password = ""

    for i in range(length):
        generated_password += ''.join(secrets.choice(characters))

    print(generated_password)
    use_password = input("Enter 'Y' if you want to add this password in our Password Manager : ").lower()
    if use_password == 'y':
        clipboard.copy(generated_password)
        print("Password copied to your clipboard!")
        time.sleep(2)
        add_credentials(mt_username, enc_dec_key)
    else:
        time.sleep(1)
        menu = input("\nEnter 'Y' if you want to go to the Program Menu \nEnter Any Key to exit: ").lower()
        if menu == 'y':
            program_menu(mt_username, enc_dec_key)
    

def website_login_page(mt_username, enc_dec_key):
    web = input("\nEnter the Website you want to login : ").lower()

    query = "SELECT * FROM credentials WHERE master_username = ? and website = ?"
    cursor = db_connection.cursor()

    try:
        cursor.execute(query, (mt_username, web))
        record = cursor.fetchone()
        if record is None:
            print("No Record Found!")
        else:
            enc_pass = record[2]
            aes = pyaes.AESModeOfOperationCTR(enc_dec_key)
            decrypted_password = aes.decrypt(enc_pass).decode('utf-8')
         
            print(f"Website URL fetched from the Database : {record[4]}")
            confirm = input("Please check the website URL!\nEnter 'Y' to confirm : ").lower()
            if confirm == 'y':
                webbrowser.open(record[4])
            # print(f"Master Username : {record[0]}") 
                print(f"\nUse your credentials to login")
                print(f"Username/Email : {record[1]}")
                clipboard.copy(decrypted_password)
                print(f"Password copied to your clipboard! ")
                time.sleep(1)
                print("Returning to the Program Menu...")
                program_menu(mt_username, enc_dec_key)
            else:
                cursor.close()
                return
    except sqlite3.Error as error:
        print("Error while viewing informaton! : ", error)
    finally:
        cursor.close()
 

def add_credentials(mt_username, enc_dec_key):
    
    website = input("\nEnter the Website name : ").lower()
    website_URL = input("Enter the Website URL : ").lower()
    username_or_email = input("Enter your username or email for the said website: ")

    while True:
        password = input("Enter the Password : ")

        if analyze_password_strength(mt_username, enc_dec_key, password):
            aes = pyaes.AESModeOfOperationCTR(enc_dec_key)
            enc_pass = aes.encrypt(password)
            # print(enc_pass)

            query = "INSERT INTO credentials (master_username, username_or_email, encrypted_pass, website, website_URL) VALUES(?,?,?,?,?)"
            db_connection.execute(query, (mt_username, username_or_email, enc_pass, website, website_URL))
            db_connection.commit()
            print("Your credentials have been added successfully!")
            time.sleep(1)
            menu = input("\nEnter 'Y' if you want to go to Program Menu \nEnter Any Key to exit: ").lower()
            if menu == 'y':
                program_menu(mt_username, enc_dec_key)
            return
        else:
            continue


def delete_credentials(mt_username, enc_dec_key):
    
    web = input("\nEnter the Website you want to delete your Credentials for : ").lower()
    
    query_for_fetching = "SELECT * FROM credentials WHERE website = ? AND master_username = ?"
    cursor = db_connection.cursor()

    try:
        cursor.execute(query_for_fetching, (web, mt_username))
        record = cursor.fetchone()
        if record is None:
            print("No Record Found!")
            time.sleep(2)
            program_menu(mt_username, enc_dec_key)
        else:
            query = "DELETE FROM credentials WHERE website = ? AND master_username = ?"
            db_connection.execute(query, (web, mt_username))
            db_connection.commit()
            print(f"Record for website '{web}' has been deleted successfully!")
            time.sleep(1)
            menu = input("\nEnter 'Y' if you want to go to Program Menu : \nEnter Any Key to exit: ").lower()
            if menu == 'y':
                program_menu(mt_username, enc_dec_key)

    except sqlite3.Error as error:
        print("Error while Deleting Credentials! : ", error)
    finally:
        cursor.close()


def update_credentials(mt_username, enc_dec_key):
    
    web = input("\nEnter the Website you want to Update your Credentials for : ").lower()

    while True:
        new_password = input("\nEnter the new password : ")
        verify_pass = input("Enter the new password again : ")
        if new_password != verify_pass:
            print("Password does not match! \n")
            continue
        else:
            if analyze_password_strength(mt_username, enc_dec_key, new_password):
                aes_algo = pyaes.AESModeOfOperationCTR(enc_dec_key)
                enc_pass = aes_algo.encrypt(new_password)
                #update logic
                query = "UPDATE credentials SET encrypted_pass = ? WHERE website = ? AND master_username = ?"
                db_connection.execute(query, (enc_pass, web, mt_username))
                db_connection.commit()
                time.sleep(1)
                menu = input("\nEnter 'Y' if you want to go to Program Menu \nEnter Any Key to exit: ").lower()
                if menu == 'y':
                    program_menu(mt_username, enc_dec_key)
                break


def view_credentials(mt_username, enc_dec_key):
    
    query = "SELECT * FROM credentials WHERE master_username = ?"
    cursor = db_connection.cursor()

    try:
        cursor.execute(query, (mt_username,))
        records = cursor.fetchall()
        print(records)
        
        if len(records) == 0:
            print("No Record Found!")
            time.sleep(2)
            program_menu(mt_username, enc_dec_key)
        else:
            # print(f"Number of records retrieved: {len(records)}")
            for record in records:
                enc_pass = record[2]
                aes = pyaes.AESModeOfOperationCTR(enc_dec_key)
                decrypted_password = aes.decrypt(enc_pass).decode('utf-8')
                print("-" * 30)
                print(f"Master Username : {record[0]}") 
                print(f"Username/Email associated with the website : {record[1]}")
                print(f"Password : {decrypted_password}")
                print(f"Webiste : {record[3]}")
                print(f"Website URL : {record[4]}")

    except sqlite3.Error as error:
        print("Error while viewing informaton! : ", error)
    finally:
        cursor.close()

    time.sleep(1)
    menu = input("\nEnter 'Y' if you want to go to Program Menu \nEnter Any Key to exit: ").lower()
    if menu == 'y':
        program_menu(mt_username, enc_dec_key)

def kdf(master_password, salt_type):
    salt_bytes = salt_type.encode() 

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  
        salt= salt_bytes,
        iterations=390000, 
    )

    key = kdf.derive(master_password.encode()) 
    return key


def insert_into_master(username, verification_key):
    query = "INSERT INTO master (username, verification_key) VALUES(?,?)"
    db_connection.execute(query, (username, verification_key))
    db_connection.commit()


def verification(username, verification_key, encryption_key):
    query = "SELECT verification_key FROM master WHERE username = ?"
    cursor = db_connection.cursor()

    try:
        cursor.execute(query, (username,))
        record = cursor.fetchone()
        if record is None or verification_key != record[0]:
                print("Invalid username or password!")
                sign_in()
        else:
            # print("verified")
            program_menu(username, encryption_key)
            # print(record[0])
            # return record[0]
    except sqlite3.Error as error:
        print("Error while verification : ", error)
        return None
    finally:
        cursor.close()


def sign_up():
    while True:
        username = input("\nEnter a username (MUST BE UNIQUE) : ")
        query = "SELECT username FROM master"
        cursor = db_connection.cursor()
        cursor.execute(query)
        usernames_fetched = cursor.fetchall()

        exists = False
        for user in usernames_fetched:
            if user[0] == username:
                exists = True
                print("Username already taken! ")
                break
        if exists:
            continue

        while True:
            if not exists:
                print("\nA Master Pasword : ")
                print("Must be At least 12 characters long but 14 or more is better.")
                print("Must be A combination of uppercase letters, lowercase letters, numbers, and symbols.")
                # https://support.microsoft.com/en-us/windows/create-and-use-strong-passwords-c5cebb49-8c53-4f5e-2bc4-fe357ca048eb

                master_password = input("Enter a strong master password : ")
                
                if analyze_password_strength("dummy_master", "dummy_key", master_password):
                    verification_salt = "salt_4_ver"
                    verification_key = kdf(master_password, verification_salt)
                    # print(verification_key)
                    insert_into_master(username, verification_key)
                    print("Your account has been created succesfully! \n\n")
                    time.sleep(1)
                    main()
                    # return
                else:
                    continue

def sign_in():
    username = input("\nEnter your username : ")

    master_password = input("Enter your master password : ")

    encryption_salt = "salt_4_enc"
    encryption_key = kdf(master_password, encryption_salt)
    # print(encryption_key)

    verification_salt = "salt_4_ver"
    verification_key = kdf(master_password, verification_salt)
    # print(verification_key)
    verification(username, verification_key, encryption_key)



def main():
    # run to create database and tables (One time only)
    # database_and_tables()
    
    print("""Enter '1' to Sign Up
Enter '2' to Sign in
Enter Any Key to exit
""")
    choice = input("Enter your Choice : ")
    if choice == '1':
        sign_up()
    elif choice == '2':
        sign_in()
    else:
        print("Exiting Program.....")
        time.sleep(1)

    db_connection.close()



if __name__ == "__main__":
    main()
