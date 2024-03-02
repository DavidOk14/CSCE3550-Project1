from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
import jwt

app = Flask(__name__)

# Generate keys
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()

# Key IDs (KID_2 is the expired key, KID_1 is valid)
KID_1 = "key_1"
KID_2 = "key_2"

# Expiration Times
expire_1 = datetime.utcnow() + timedelta(days=1)    #valid time
expire_2 = datetime.utcnow() - timedelta(days=1)    #expired time

# Define keys
keys = \
    {
    KID_1:
        {
        "kty": "RSA",
        "kid": KID_1,
        "n": str(public_key.public_numbers().n),
        "e": str(public_key.public_numbers().e),
        "exp": expire_1.isoformat()
        },

    KID_2:
        {
        "kty": "RSA",
        "kid": KID_2,
        "n": str(public_key.public_numbers().n),
        "e": str(public_key.public_numbers().e),
        "exp": expire_2.isoformat(),
        }
}

#Send JWKS to proper route when the GET request is sent
@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks():
    return jsonify({"keys": list(keys.values())})

#Auth endpoint for generating the JWTs
@app.route("/auth", methods=['POST'])
def auth():
    #Start creating the data for the JWT to be tested against the JWK
    if request.args.get("expired") == "true":
        kid = KID_2
        exp = -3600
    else:
        kid = KID_1
        exp = datetime.utcnow() + timedelta(days=1)

    payload = {"name": "David O"}

    headers = {"kid": kid, "exp": exp}

    #Encode JWT and return it
    token = jwt.encode(payload, private_key, algorithm='RS256', headers=headers)

    return jsonify({"token": token})


if __name__ == "__main__":

    #Run the program on port 8080 of localhost
    app.run(port=8080)