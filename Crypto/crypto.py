import dropbox
from PIL import Image
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Hash import SHA256
import os, random
import json
import md5
import hashlib

access_token = "17zzkKkVPvAAAAAAAAABGOf887gJPFdkEFC8FVJ0jmP4Dz6_XXFBMcKCxdBBAs_2"
# file_from = 'Crypto.pdf'
# file_to = '/crypto/Crypto.pdf'


def upload_file(file_from, file_to,fhash):
    dbx = dropbox.Dropbox(access_token)
    f = open(file_from, 'rb')
    dbx.files_upload(f.read(), fhash)
    for entry in dbx.files_list_folder('').entries:
        print(entry.name)

def downloadFile(f,h):
    dbx = dropbox.Dropbox(access_token)
    # for entry in dbx.files_list_folder(folder).entries:
    #     print(entry.name)
    # print(dbx.files_get_metadata("/crypto/"+entry.name))
    # f = f+".enc"
    dbx.files_download_to_file(f, '/crypto/'+str(h))

# def enc():
#     img = Image.open("index.png")
#     img.tobytes()

    # key = 'vaikunthpatel'
    # mode = AES.MODE_ECB
    # encryptor = AES.new(key, mode)
    #
    # img.frombytes("RGB")


# -----------------------------------------------------------------------
# In this method we encrypt the data of file

# We perform symmetric encryption using AES - CBC mode algorithm

# Block level encryption API of PyCrypto is low level
# and it requires input to consist of 16-byte blocks


def encrypt(key, filename):
    block_size = 64*1024
    output_file = filename+".enc"
    file_size = str(os.path.getsize(filename)).zfill(16)
    Int_Vector = ''

    #Using python's random we generate pseudo-random number for intialization vector
    for i in range(16):
        Int_Vector += chr(random.randint(0, 0xFF))

    #New object of AES encryptor is created for encryption
    encryption = AES.new(key, AES.MODE_CBC, Int_Vector)


    with open(filename, 'rb') as inputfile:
        with open(output_file, 'wb') as outfile:
            outfile.write(file_size)
            outfile.write(Int_Vector)
            while True:
                block = inputfile.read(block_size)
                if len(block) == 0:
                    break
                elif len(block) % 16 != 0:
                   block += ' '*(16 - len(block)%16)
                outfile.write(encryption.encrypt(block))




#In this method we decrypt the data of file

# We perform symmetric decryption using AES - CBC mode algorithm

def decrypt(key, filename):
        block_size = 64*1024
        output_file = filename[:-4]
        with open(filename, 'rb') as infile:
            file_size = long(infile.read(16))
            Int_Vector = infile.read(16)

            #New object of AES encryptor is created for decryption
            decryption = AES.new(key, AES.MODE_CBC, Int_Vector)

            with open(output_file, 'wb') as outfile:
                while True:
                    block = infile.read(block_size)
                    if len(block)==0:
                        break
                    outfile.write(decryption.decrypt(block))
                outfile.truncate(file_size)

#The password provided by user is used as key for encrypting file
#In this method simple hashing is performed using SHA-256 on passsword
def getKey(password):
    hasher = SHA256.new(password)
    return hasher.digest()


#In this method we use the hashed value generated from filename
#And we link the keyword with hash value which will be useful while searching for file
def storeKeywords(f,h):
    fname = f.split(".")[0]
    data = fname.split(" ")
    reg_file = open("reg.json","r")
    reg = json.loads(reg_file.read())
    reg_file.close()
    for i in data:
        if i in reg:
            reg[i].append(h)
        else:
            reg[i] = []
            reg[i].append(h)
    open("reg.json","w").write(json.dumps(reg))

#This method checks for files linked with same keyword
#It returns the number of files having keyword in common and uses different method to separate such files
def getNumberOfFilesFromKeyWords(k):
    words = k.split(" ")
    reg_file = open("reg.json","r")
    reg = json.loads(reg_file.read())
    holder = []
    for i in words:
        if len(holder) <= 0:
            holder = reg[i]
        else:
            l1 = reg[i]
            holder = intersection(holder,l1)
    return holder

#Takes input keyword from user to search file
#This keyword is passed to method above to check the number of files having keywords in common
def getInput():
    keyword = raw_input("Please Input Key Word: ")
    return getNumberOfFilesFromKeyWords(keyword)


def getFileName(h):
    f = open('index.json','r')
    data = json.loads(f.read())
    return data[h]

#This method is used to separate files having keywords in common
def intersection(lst1, lst2):
    lst3 = [value for value in lst1 if value in lst2]
    return lst3

def main():
    choice = raw_input("Select One of the following\n> 1. Encrypt \n> 2. Decrypt\n>>> ")

    #Encryption on file data is performed when option 1 is selected
    if choice == "1":
        filename = raw_input("Enter the name of file to be encrypted >> ")
        password = raw_input("Enter the password:")

        # Using the SHA-256 we perform simple hashing on the filename

        nameHasher = hashlib.sha256(filename.encode('utf-8')).hexdigest()
        print(nameHasher)

        #In index.json the file is linked with the hash generated from the filename

        f = open("index.json","r")
        data = json.loads(f.read())
        f.close()
        data[nameHasher]= filename
        f = open("index.json","w").write(json.dumps(data))

        #
        encrypt(getKey(password), filename)
        storeKeywords(filename,nameHasher)
        upload_file(filename+".enc","/crypto/"+filename,"/crypto/"+nameHasher)
        print "Done!\n%s ==> %s"%(filename, filename+".enc")

        #Decryption on file data is performed when option 2 is selected
    elif choice == "2":
        x = getInput()
        while(len(x)!=1):
            print("Possible Files are "+str(len(x)))
            x = getInput()
        password = raw_input("Password: ")
        filename = getFileName(x[0])
        print(filename)
        downloadFile(filename , x[0])
        decrypt(getKey(password), filename+".enc")
        print "Done\n%s ==> %s"%(filename, filename[:-4])
    else:
        print "No option Selected"

# upload_file(file_from,file_to)

# getList("/crypto")

if __name__ == "__main__":
    main()
