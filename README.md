# Secure-Passwords

## Overview
This Python program securely manages website passwords. It encrypts credentials, analyzes password strength, and lets you add, delete, update, and view them (decrypted for a short time). It can also open website login pages or copy passwords to your clipboard. Currently educational, it lays the foundation for a robust password management solution. 

## Password Manager Program Functions:

**database_and_tables()**

* **Purpose:** Creates the initial database and tables for storing user information and encrypted credentials.
* **Parameters:** None
* **Returns:** None (prints confirmation message)

**program_menu(mt_username, enc_dec_key)**

* **Purpose:** Presents the main menu with options for adding, deleting, updating, viewing, and managing website credentials.
* **Parameters:**
    * `mt_username`: Master username for the current session.
    * `enc_dec_key`: Encryption/Decryption key derived from the master password.
* **Returns:** None

**analyze_password_strength(mt_username, enc_dec_key, password_to_check)**

* **Purpose:** Analyzes the strength of a given password based on length and character types (uppercase, lowercase, digits, symbols).
* **Parameters:**
    * `mt_username`: Master username (not used in current implementation).
    * `enc_dec_key`: Encryption/Decryption key (not used in current implementation).
    * `password_to_check`: The password to be analyzed.
* **Returns:** String indicating password strength ("Weak", "Medium", "Strong")

**password_generator(mt_username, enc_dec_key)**

* **Purpose:** Generates a random password based on user-specified criteria (length, character types).
* **Parameters:**
    * `mt_username`: Master username (not used in current implementation).
    * `enc_dec_key`: Encryption/Decryption key (not used in current implementation).
* **Returns:** None (generated password is displayed and offered for addition to password manager)

**website_login_page(mt_username, enc_dec_key)**

* **Purpose:** Retrieves the website URL from stored credentials for a specific website and opens it in the default web browser. Also decrypts and copies the password to the clipboard for a limited time.
* **Parameters:**
    * `mt_username`: Master username for the current session.
    * `enc_dec_key`: Encryption/Decryption key derived from the master password.
* **Returns:** None

**add_credentials(mt_username, enc_dec_key)**

* **Purpose:** Adds new website credentials (username/email and password) to the database after encrypting the password.
* **Parameters:**
    * `mt_username`: Master username for the current session.
    * `enc_dec_key`: Encryption/Decryption key derived from the master password.
* **Returns:** None (prints confirmation message)

**delete_credentials(mt_username, enc_dec_key)**

* **Purpose:** Deletes credentials for a specific website from the database.
* **Parameters:**
    * `mt_username`: Master username for the current session.
    * `enc_dec_key`: Encryption/Decryption key derived from the master password.
* **Returns:** None (prints confirmation message)

**update_credentials(mt_username, enc_dec_key)**

* **Purpose:** Updates the password for a specific website after encrypting the new password.
* **Parameters:**
    * `mt_username`: Master username for the current session.
    * `enc_dec_key`: Encryption/Decryption key derived from the master password.
* **Returns:** None (prints confirmation message)

**view_credentials(mt_username, enc_dec_key)**

* **Purpose:** Retrieves and decrypts all website credentials stored for the current user, displaying them for a limited time.
* **Parameters:**
    * `mt_username`: Master username for the current session.
    * `enc_dec_key`: Encryption/Decryption key derived from the master password.
* **Returns:** None (credentials are displayed)

**kdf(master_password, salt_type)**

* **Purpose:** Derives a strong encryption key from the master password using a Key Derivation Function (KDF) with added salt.
* **Parameters:**
    * `master_password`: The user's master password.
    * `salt_type`: String specifying the type of salt to be used.
* **Returns:** The derived encryption key (bytes)

**insert_into_master(username, verification_key)**

* **Purpose:** Inserts a new user record into the "master" table, storing the username and verification key derived from the master password.
* **Parameters:**
    * `username`: The user's chosen username.
    * `verification_key`: The KDF-derived key used for verification during sign-in.
* **Returns:** None (data is inserted into the database)

**verification(username,
