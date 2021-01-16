import base64
import cryptography.exceptions
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key

# Load the public key.
with open('public.pem', 'rb') as f:
    public_key = load_pem_public_key(f.read(), default_backend())

# Load the payload contents and the signature.
with open('signer.py', 'rb') as f:
    payload_contents = f.read()
with open('signature.sig', 'rb') as f:
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
    print('ERROR: Payload and/or signature files failed verification!')