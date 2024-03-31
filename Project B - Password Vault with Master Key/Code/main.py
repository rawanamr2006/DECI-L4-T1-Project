# Setup & Imports 
import getpass, hashlib, os, string
from cryptography.fernet import Fernet

# Some Variables
run = True
takingInput = True
loginAttempts = 0

# Functions

# To Check key complexity before key creation
def isMasterKeyComplex(key):
    # intializing our characters list in each type 
    lowercase_alphabet = list(string.ascii_lowercase)
    uppercase_alphabet = list(string.ascii_uppercase)
    symbols = ["@", "?","=", "<",">",":","{", "}","!", "#", "%", "$", "*", "&", "^", "~", "'", ";", "/", "-", "_", "(", ")"]
    numbers = [0,1,2,3,4,5,6,7,8,9]

    # simple function to be used later in formatting output string
    checkOrNot = lambda cond : "(√)" if cond else "(X)"

    # complexity checks
    contains_number_and_symbol = any(str(i) in key for i in numbers) and any(i in key for i in symbols)
    contains_lower_and_upper_case = any(i in key for i in uppercase_alphabet) and any(i in key for i in lowercase_alphabet)
    is_12_or_more_charcters = len(key) >= 12

    isComplex =  contains_number_and_symbol & contains_lower_and_upper_case & is_12_or_more_charcters

    # displaying the check results to the user
    output = """\nKey Complexity Policy Rules:

        1.length is 12 or more characters {}
        2.contains uppercase and lowercase letters {}
        3.contains a number and a symbol {}
        """.format(checkOrNot(is_12_or_more_charcters), checkOrNot(contains_lower_and_upper_case), checkOrNot(contains_number_and_symbol))
    
    print(output)
    return isComplex

# To Create Master key
def createMasterKey():
    new_master_key = getpass.getpass("\nInput your new master key to be created(hidden, type anyway): ")

    if isMasterKeyComplex(new_master_key):
        new_master_key = bytes(new_master_key, "utf-8")

        # Master key creation, hashing and storing hashed key
        hashed_key = hashlib.sha256(new_master_key).hexdigest()

        master_key_file = open("master_key.mkey", "x")
        master_key_file.write(hashed_key)

        master_key_file.close()

        print("Master Key Created Successfully !\n")
    else:
        print("\nThe entered Master key doesn't follow the master key complexity policy, Try again...\n")
        createMasterKey()

# To Compare the key entered by user with the original key previously stored
def verifyKey():
    master_key = bytes(getpass.getpass("\nInput your master key to authenticate: \n"), "utf-8")
    hashed_key = hashlib.sha256(master_key).hexdigest()

    with open("master_key.mkey", "r") as real_key_file:
        real_master_key = real_key_file.read()

    return real_master_key == hashed_key

# To Perform authentication process and proceed with normal operation
def authenticate():
    global loginAttempts, takingInput, run

    # In case of successful authN
    if verifyKey():
        print("\nAuthentication Success !\n")

        loginAttempts = 0
        takingInput = True

        while takingInput:
            prompt = input("\nPress 'i' to input new password record or 'r' to retreive stored data or 'q' to quit ('i' or 'r' or 'q'): ")

            if prompt == "q":
                takingInput = False
            elif prompt == "i":
                takeInput()
            elif prompt == "r":
                retreivePassword()
            else:
                print("\nInvalid option !! try a valid one ...")

    # In case of failed authN (Limiting Authentication attempts to prevent Brute Force Attacks)
    else:
        loginAttempts += 1
        if loginAttempts <= 4:
            print("\nInvalid Key, Try again...")
            authenticate()
        else:
            print("Login attempts Exceeded the Limit and you are locked out ! Try again Later..")
            run = False

# To Take user input to add new password entry
def takeInput():
    print("\nFill the following fields to store your password: \n")
    domain = input("Domain/website: ")
    username = input("username: ")
    password = bytes(getpass.getpass("Password(hidden, type anyway): "), "utf-8")

    # Check if any field is left blank 
    if domain == "" or username == "" or password == "":
        print("\nNo field can be Left BLANK, Please fill all the fields.\n")
        takeInput()

    key = Fernet.generate_key()
    f = Fernet(key)

    # Password Encryption & Hashing
    encrypted_passwd = f.encrypt(password)
    hashed_passwd = hashlib.sha256(password).hexdigest()

    # Password Entry Storage
    entry = ":".join([domain,username,key.decode("utf-8"),encrypted_passwd.decode("utf-8") ,hashed_passwd])
    
    with open("vault.vlt", "a") as vault:
        vault.write("\n" + entry)

    vault.close()

# To Retreive a previously stored password entry from the vault 
def retreivePassword():
    requested_domain = input("\nDomain: ")
    found = False

    with open("vault.vlt", "r") as vault:
        for line in vault.readlines()[1:]:
            domain,username,key,encrypted_passwd ,hashed_passwd = line.split(":")
            
            if domain == requested_domain:
                f = Fernet(key)

                # Decrepting Password
                passwd = f.decrypt(bytes(encrypted_passwd, "utf-8"))
                
                # Returning password entry information to user
                print("\nCredentials for", domain, "\nUsername: ", username, "\nPassword: ", passwd.decode("utf-8"))
                found = True

        if not found: 
            print("\nDidn't find the domain you requested, Search for a valid domain...")

    vault.close()


# Program's Main Loop 

while run:
    action = input("\nPress 'k' for master key creation. If already done press 'a' to authenticate or 'q' to quit ('k' or 'a' or 'q'): ")

    # Checkig if user wants to quit
    if action == "q":
        run = False
    
    # Master Key Creation and Hashing
    elif action == "k":
        if os.path.exists("master_key.mkey"):
            print("\nA Master Key Already Exists.\nYou have already created a master key.")
            authenticate()
        else:
            createMasterKey()

    # Authentication and key verification        
    elif action == "a": 
        if os.path.exists("master_key.mkey"):
            authenticate()
        else:
            print("\nNo Master Key created.\nYou have to create a master key first.\n")
            createMasterKey()

    # Error Handling
    else:
        print("\nInvalid option !! try a valid one ...")