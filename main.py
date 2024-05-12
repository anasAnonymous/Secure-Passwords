"""
Functions to implement:
    Add/delete/update/view passwords
    strength checker
    password generator


Database:
Tables:
    master  (id, pass, verKey(KDF))
    data    (username/email,  encPass(AES 256),  website,  website login page URL)
    log     (action, uID)

    

Libraries:
    generator:          secret, random
    strength:           zxcvbn    
    cryptography:       encryption/decryption.
    pyotp (Optional):   MFA.
"""

import sqlite3
# import secrets
# import random
# import zxcvbn
# import cryptography
# import pyotp

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import pyaes    # for AES
# https://stackoverflow.com/questions/25261647/python-aes-encryption-without-extra-module

db_connection = sqlite3.connect("passwords_DB.db")

def database_and_tables():
    print("Alhamdulillah! db created")

    db_connection.execute("""CREATE TABLE IF NOT EXISTS master(     
                 username VARCHAR(30) PRIMARY KEY,
                 verification_key TEXT
    );
    """)

    # db_connection.execute("DROP TABLE credentials")

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
    print("""Enter '1' to Add a Password
Enter '2' to Delete a Password
Enter '3' to Update your Password
Enter '4' to View your Passwords
Enter '5' to exit
""")
    choice = input("Enter your Choice : ")
    if choice == '1':
        add_password(mt_username, enc_dec_key)
    elif choice == '2':
        delete_password(mt_username)
    elif choice == '3':
        update_password(mt_username, enc_dec_key)
    elif choice == '4':
        view_password(mt_username, enc_dec_key)
    elif choice == '5':
        return
    else:
        print("Invalid Input!")
        program_menu()


def add_password(username, enc_dec_key):
    # print("add password")
    website = input("Enter the Website name : ").lower()
    website_URL = input("Enter the Website URL : ").lower()
    username_or_email = input("Enter your username or email for the said website: ")
    password = input("Enter the Password : ")

    # wanna analyze password strength?      -->     strength()
    aes = pyaes.AESModeOfOperationCTR(enc_dec_key)
    enc_pass = aes.encrypt(password)
    # print(enc_pass)

    query = "INSERT INTO credentials (master_username, username_or_email, encrypted_pass, website, website_URL) VALUES(?,?,?,?,?)"
    db_connection.execute(query, (username, username_or_email, enc_pass, website, website_URL))
    db_connection.commit()


def delete_password(mt_username):
    # print("delete password")
    web = input("Enter the Website you want to delete your Credentials for : ").lower()
    
    query_for_fetching = "SELECT * FROM credentials WHERE website = ? AND master_username = ?"
    cursor = db_connection.cursor()

    try:
        cursor.execute(query_for_fetching, (web, mt_username))
        record = cursor.fetchone()
        if record is None:
            print("No Record Found!")
        else:
            query = "DELETE FROM credentials WHERE website = ? AND master_username = ?"
            db_connection.execute(query, (web, mt_username))
            db_connection.commit()
            print(f"Record for website '{web}' has been deleted successfully!")

    except sqlite3.Error as error:
        print("Error while Deleting Credentials! : ", error)
    finally:
        cursor.close()


def update_password(mt_username, enc_dec_key):
    # print("update password")
    web = input("Enter the Website you want to Update your Credentials for : ").lower()

    while True:
        new_password = input("Enter the new password : ")
        verify_pass = input("Enter the new password again : ")
        if new_password != verify_pass:
            print("Password does not match! \n")
            continue
        else:
            # print("on")
            #update logic
            aes_algo = pyaes.AESModeOfOperationCTR(enc_dec_key)
            enc_pass = aes_algo.encrypt(new_password)
            query = "UPDATE credentials SET encrypted_pass = ? WHERE website = ? AND master_username = ?"
            db_connection.execute(query, (enc_pass, web, mt_username))
            db_connection.commit()
            #   wanna analyze password strength?      -->     strength()
            break


def view_password(mt_username, enc_dec_key):
    # print("view password")
    query = "SELECT * FROM credentials WHERE master_username = ?"
    cursor = db_connection.cursor()

    try:
        cursor.execute(query, (mt_username,))
        records = cursor.fetchall()
        if records is None:
            print("No Record Found!")
        else:
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
            print("verified")
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
        username = input("Enter a username (MUST BE UNIQUE) : ")
        #check if alr exists (DB)
        query = "SELECT username FROM master"
        cursor = db_connection.cursor()
        cursor.execute(query)
        usernames_fetched = cursor.fetchall()

        exists = False
        for user in usernames_fetched:
            if user[0] == username:
                exists = True
                print("Username already exists! ")
                break
        if not  exists:
            master_password = input("Enter a strong master password (specify characteristics): ")
            #strength condition verify 

            verification_salt = "salt_4_ver"
            verification_key = kdf(master_password, verification_salt)
            # print(verification_key)
            insert_into_master(username, verification_key)
            return


def sign_in():
    username = input("Enter your username : ")

    master_password = input("Enter your master password (acc to the specified characteristics): ")
    #strength condition verify 

    encryption_salt = "salt_4_enc"
    encryption_key = kdf(master_password, encryption_salt)
    # print(encryption_key)

    verification_salt = "salt_4_ver"
    verification_key = kdf(master_password, verification_salt)
    # print(verification_key)
    verification(username, verification_key, encryption_key)



def main():
    print("main")
    # database_and_tables()
    # sign_up()
    sign_in()
    # program_menu()
    # update_password("mt", "enc")

    # LASTTTTTTTTTTTTTTT
    db_connection.close()



if __name__ == "__main__":
    main()





"""

Master Password:
    - Don't store the master password itself in the database.
    - Consider using a technique like key derivation function (KDF) to generate a key from the master password that's used for encryption/decryption.


MFA (Optional):
    - Explore libraries like pyotp to integrate Multi-Factor Authentication using one-time passwords generated by an authenticator app.



Deriving a Verification Key:

Don't store the master password itself.
When a user creates an account, collect their master password.
Instead of storing it directly, use a Key Derivation Function (KDF) to derive two separate keys from the master password:
Encryption Key: Used to encrypt and decrypt stored passwords (as discussed earlier).
Verification Key: Used for user authentication during login attempts.


Verification Process:

During login, the user enters their master password.
The application applies the same KDF function (used during account creation) to the entered master password.
The derived verification key is compared to the stored verification key for that user.
If they match, the user is successfully authenticated.


--- sign UP   
    input (master pass)
    kdf (mp)    ->     encKey, verKey
    storeInDB(verKey)

    sign INN
    input (master pass)
    kdf (mp)    ->     encKey, verKey
    verify (verKeyDB == verKeyGenerated)
    viewPass (encDecKey)

"""
