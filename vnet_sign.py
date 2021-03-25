import base64
import cryptography.exceptions
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import rsa
from verifier_dicts import vd
import random

import pymongo
import yaml
import os
import glob

# set the config in config/config.yaml
# needs fields db, table, address
with open(r'config/config.yaml') as file:
    doc = yaml.load(file, Loader=yaml.FullLoader)
    db = doc["db"]
    tab = doc["table"]
    address = doc["address"]
    dbc = pymongo.MongoClient(address)
    varcom = dbc[db]
    col = varcom[tab]


# generate public and private keys
def gen_keys():
    # Generate the public/private key pair.
    private_key = rsa.generate_private_key(
        public_exponent = 65537,
        key_size = 4096,
        backend = default_backend(),
    )

    # Save the private key to a file.
    with open('keys/private.key', 'wb') as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    # Save the public key to a file.
    with open('keys/public.pem', 'wb') as f:
        f.write(
            private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

def generate_special_fmt_key(pub_exp, key_s, privkey_fname, pubkey_fname):
    """

    :param pub_exp: public exponent of key gen
    :param key_s:   key size
    :return:
    """
    private_key = rsa.generate_private_key(
        public_exponent = pub_exp,
        key_size = key_s,
        backend = default_backend(),
    )
    with open(f'keys/{privkey_fname}', 'wb') as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    with open(f'keys/{pubkey_fname}', 'wb') as f:
        f.write(
            private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )




# sign a file with your private key
def sign(file, privkey=None):
    if privkey is None:
        with open(f'keys/private.key', 'rb') as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend(),
            )

    else:
        with open(f'{privkey}', 'rb') as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend(),
            )

    # Load the contents of the file to be signed.
    with open(f'{file}', 'rb') as f:
        payload = f.read()

    # Sign the payload file.
    signature = base64.b64encode(
        private_key.sign(
            payload,
            padding.PSS(
                mgf = padding.MGF1(hashes.SHA256()),
                salt_length = padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
    )
    with open(f'signatures/{file}.sig', 'wb') as f:
        f.write(signature)


# verify signed code is from a trusted source
def verify(file2, key=None):
    # Load the public key.
    if key is None:
        with open(f'keys/public.pem', 'rb') as f:
            public_key = load_pem_public_key(f.read(), default_backend())

    else:
        with open(f'{key}', 'rb') as f:
            public_key = load_pem_public_key(f.read(), default_backend())

    # Load the payload contents and the signature.
    with open(f'{file2}', 'rb') as f:
        payload_contents = f.read()
    with open(f'signatures/{file2}.sig', 'rb') as f:
        signature = base64.b64decode(f.read())

    # Perform the verification.
    try:
        public_key.verify(
            signature,
            payload_contents,
            padding.PSS(
                mgf = padding.MGF1(hashes.SHA256()),
                salt_length = padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
    except cryptography.exceptions.InvalidSignature as e:
        # print('ERROR: Payload and/or signature files failed verification!')
        return -1
    return 0


# class for the verifier. includes all info needed to sign and
# verify the files.
class VNETverify:
    def __init__(self, keys=None, sigd=None, files=None):
        if keys is None:
            self.keydir = "keys/"
            self.privkey = "keys/private.key"
            self.pubkey = "keys/public.pem"
        else:
            self.keydir = keys
            self.privkey = f"{keys}private.key"
            self.pubkey = f"{keys}public.pem"
        if sigd is None:
            self.sigdir = "signatures/"
        else:
            self.sigdir = sigd
        if files is None:
            self.files = []
        else:
            self.files = files
        self.num_bad_files = 0
        self.probfiles = []  # problem files
        self.goodfiles = []  # files that pass verification
        self.sigreel = []  # list of signatures to be compared against self.files
        self.fdict = {}    # dictionary for transaction
        self.dict_id = ""

    # sign the files here
    # append to the sigreel
    def sign_files(self):
        for f in self.files:
            sign(f)
            self.sigreel.append(f"{f}.sig")

    # add a file to the list of signatures
    def add_file(self, f):
        self.files.append(f)

    # verify signed files are indeed signed properly
    def verify_files(self):
        for f in self.files:
            if verify(f) == -1:
                print(f"ERROR: file {f} did not verify!")
                self.num_bad_files += 1
                self.probfiles.append(f)
            else:
                print(f"verified file {f}")
                self.goodfiles.append(f)
        # print(self.files)
        # print(self.goodfiles)
        if self.files == self.goodfiles:
            print("all files verified!")
            return True
        else:
            print("files NOT VERIFIED.")
            return False

    # generate reel of files to be verified. will be compared
    # to other
    def generate_sigreel(self):
        dict2 = {}
        dict2 = vd.verify_dict
        self.dict_id = random.randint(1000000, 9999999)
        dict2["id"] = self.dict_id
        dict2["files"] = self.files
        dict2["signatures"] = self.sigreel
        with open(f'keys/public.pem', 'rb') as f:
            public_key = f.read()
            dict2["pubkey"] = f"{public_key}"
        self.fdict = dict2
        print(self.dict_id)

    # insert into mongo
    def insert_transaction_mongoid(self):
        col.insert_one(self.fdict)
        return

    def sign_all_files_in_directory(self, directory):
        """

        :param directory: a directory to sign all files in
        :return:
        """
        for file in os.listdir(directory):
            print(file)


class SignedFileNetworkManager:
    def __init__(self):
        return


if __name__ == "__main__":
    # note: by default, verify will look in the keys/ dir for keys.
    # you can specify your own path to key if you want.
    # gen_keys()
    # sign('loremipsum.py')
    # if verify('loremipsum.py') == -1:
        # print("ERROR: failed verifying files!")
    # elif verify('loremipsum.py') == 0:
        # print("signed and verified!")
    s = VNETverify(files=["loremipsum.py", "verifier.py", "signer.py", "README.md"])
    s.sign_files()
    print(s.files)
    if s.verify_files() == True:
        print("done, no errors")
    else:
        print("errors during verification")
    s.generate_sigreel()
    s.insert_transaction_mongoid()
    s.sign_all_files_in_directory("signatures/")

