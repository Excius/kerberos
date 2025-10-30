
tgt_secret_key="V2FHYjdlb2FVbmhMVnhXQzd2NVl2TWRONm5kTk1rcFc="
encrypted_data="lyh0ITgcK4u3hAkNKlfi+IR+qg9zacKrPyBK1xrMNaj6L4WbHTW2bbZb2bkbPcYVvtDqv1hUq7mI3M2VU/SbNgmqrX4jjNkpn8Uc8icIzH0aGT1ySK7jKan4NfCLwSkodvE/cWNtI9/y8FaFpessir+OQ70dCeHLAkbnP3vE68HkLWr5wobWf/ipI6bCLtdKexc+VTF418LgFmxb4tSHgwtyqSUm1OcmsMFpyvf+vpkyPR3rnQVkkWs="

import base64
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization 

def decrypt_with_secret_key(tgt_secret_key, encrypted_data):
    """Decrypts the session key using the TGT secret key."""
    secret_key = base64.b64decode(tgt_secret_key)
    
    