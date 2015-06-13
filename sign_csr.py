import argparse, subprocess, json, os, urllib2, sys, base64, binascii, ssl, \
    hashlib, tempfile, re, time, copy, textwrap

def sign_csr(pubkey, csr):
    """Use the ACME protocol to get an ssl certificate signed by a
    certificate authority.

    :param string csr: Path to the certificate signing request.

    :returns: Signed Certificate (PEM format)
    :rtype: string

    """
    #CA = "http://localhost:4000/acme"
    CA = "https://www.letsencrypt-demo.org/acme"
    nonce_req = urllib2.Request("{}/new-reg".format(CA))
    nonce_req.get_method = lambda : 'HEAD'

    def _b64(b):
        "Shortcut function to go from bytes to jwt base64 string"
        return base64.urlsafe_b64encode(b).replace("=", "")

    def _a64(a):
        "Shortcut function to go from jwt base64 string to bytes"
        return base64.urlsafe_b64decode(str(a + ("=" * (len(a) % 4))))

    #Step 1: Get account public key
    sys.stderr.write("Reading pubkey file...\n")
    proc = subprocess.Popen(["openssl", "rsa", "-pubin", "-in", pubkey, "-noout", "-text"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = proc.communicate()
    if proc.returncode != 0:
        raise IOError("Error loading {}".format(pubkey))
    pub_hex, pub_exp = re.search("Modulus\:\s+00:([a-f0-9\:\s]+?)Exponent\: ([0-9]+)", out, re.MULTILINE|re.DOTALL).groups()
    pub_mod = binascii.unhexlify(re.sub("(\s|:)", "", pub_hex))
    pub_mod64 = _b64(pub_mod)
    pub_exp = int(pub_exp)
    pub_exp = "{0:x}".format(pub_exp)
    pub_exp = "0{}".format(pub_exp) if len(pub_exp) % 2 else pub_exp
    pub_exp = binascii.unhexlify(pub_exp)
    pub_exp64 = _b64(pub_exp)
    header = {
        "alg": "RS256",
        "jwk": {
            "e": pub_exp64,
            "kty": "RSA",
            "n": pub_mod64,
        },
    }
    sys.stderr.write("Found public key!\n".format(header))

    #Step 2: Get the domain name to be certified
    sys.stderr.write("Reading csr file...\n")
    proc = subprocess.Popen(["openssl", "req", "-in", csr, "-noout", "-text"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = proc.communicate()
    if proc.returncode != 0:
        raise IOError("Error loading {}".format(csr))
    domain = re.search("Subject:.*? CN=([^\s,;/]+).*?", out, re.MULTILINE|re.DOTALL).groups()[0]
    sys.stderr.write("Found domain '{}'\n".format(domain))

    #Step 2: Generate the payloads that need to be signed
    #registration
    reg_email = "webmaster@{}".format(domain)
    reg_raw = json.dumps({
        "contact": ["mailto:{}".format(reg_email)],
        "agreement": "https://www.letsencrypt-demo.org/terms",
    }, sort_keys=True, indent=4)
    reg_b64 = _b64(reg_raw)
    try:
        urllib2.urlopen(nonce_req).info()
    except urllib2.HTTPError as e:
        reg_nonce = json.dumps({
            "nonce": e.hdrs.get("replay-nonce", _b64(os.urandom(16))),
        }, sort_keys=True, indent=4)
        reg_nonce64 = _b64(reg_nonce)
    reg_file = tempfile.NamedTemporaryFile(dir=".", prefix="register_", suffix=".json")
    reg_file.write("{}.{}".format(reg_nonce64, reg_b64))
    reg_file.flush()
    reg_file_name = os.path.basename(reg_file.name)
    reg_file_sig = tempfile.NamedTemporaryFile(dir=".", prefix="register_", suffix=".sig")
    reg_file_sig_name = os.path.basename(reg_file_sig.name)

    #identifier
    id_raw = json.dumps({"identifier": {"type": "dns", "value": domain}}, sort_keys=True)
    id_b64 = _b64(id_raw)
    try:
        urllib2.urlopen(nonce_req).info()
    except urllib2.HTTPError as e:
        id_nonce = json.dumps({
            "nonce": e.hdrs.get("replay-nonce", _b64(os.urandom(16))),
        }, sort_keys=True, indent=4)
        id_nonce64 = _b64(id_nonce)
    id_file = tempfile.NamedTemporaryFile(dir=".", prefix="domain_", suffix=".json")
    id_file.write("{}.{}".format(id_nonce64, id_b64))
    id_file.flush()
    id_file_name = os.path.basename(id_file.name)
    id_file_sig = tempfile.NamedTemporaryFile(dir=".", prefix="domain_", suffix=".sig")
    id_file_sig_name = os.path.basename(id_file_sig.name)

    #challenge
    test_path = _b64(os.urandom(16))
    test_raw = json.dumps({
        "type": "simpleHttps",
        "path": test_path,
    }, sort_keys=True, indent=4)
    test_b64 = _b64(test_raw)
    try:
        urllib2.urlopen(nonce_req).info()
    except urllib2.HTTPError as e:
        test_nonce = json.dumps({
            "nonce": e.hdrs.get("replay-nonce", _b64(os.urandom(16))),
        }, sort_keys=True, indent=4)
        test_nonce64 = _b64(test_nonce)
    test_file = tempfile.NamedTemporaryFile(dir=".", prefix="challenge_", suffix=".json")
    test_file.write("{}.{}".format(test_nonce64, test_b64))
    test_file.flush()
    test_file_name = os.path.basename(test_file.name)
    test_file_sig = tempfile.NamedTemporaryFile(dir=".", prefix="challenge_", suffix=".sig")
    test_file_sig_name = os.path.basename(test_file_sig.name)

    #Step 3: Ask the user to sign the payloads
    sys.stderr.write("""
STEP 1: You need to sign some files (replace 'user.key' with your user private key).

openssl dgst -sha256 -sign user.key -out {} {}
openssl dgst -sha256 -sign user.key -out {} {}
openssl dgst -sha256 -sign user.key -out {} {}

""".format(
    reg_file_sig_name, reg_file_name,
    id_file_sig_name, id_file_name,
    test_file_sig_name, test_file_name))

    stdout = sys.stdout
    sys.stdout = sys.stderr
    raw_input("Press Enter when you've run the above commands in a new terminal window...")
    sys.stdout = stdout

    #Step 4: Load the signatures
    reg_file_sig.seek(0)
    reg_sig64 = _b64(reg_file_sig.read())
    id_file_sig.seek(0)
    id_sig64 = _b64(id_file_sig.read())
    test_file_sig.seek(0)
    test_sig64 = _b64(test_file_sig.read())

    #Step 5: Register the user
    sys.stderr.write("Registering {}...\n".format(reg_email))
    reg_data = json.dumps({
        "header": header,
        "protected": reg_nonce64,
        "payload": reg_b64,
        "signature": reg_sig64,
    }, sort_keys=True, indent=4)
    try:
        resp = urllib2.urlopen("{}/new-reg".format(CA), reg_data)
        result = json.loads(resp.read())
    except urllib2.HTTPError as e:
        err = e.read()
        #skip already registered accounts
        if "Registration key is already in use" in err:
            sys.stderr.write("Already registered. Skipping...\n")
        else:
            sys.stderr.write("Error: reg_data:\n")
            sys.stderr.write(reg_data)
            sys.stderr.write("\n")
            sys.stderr.write(err)
            sys.stderr.write("\n")
            raise

    #Step 6: Get simpleHttps challenge token
    sys.stderr.write("Requesting challenges...\n")
    id_data = json.dumps({
        "header": header,
        "protected": id_nonce64,
        "payload": id_b64,
        "signature": id_sig64,
    }, sort_keys=True, indent=4)
    try:
        resp = urllib2.urlopen("{}/new-authz".format(CA), id_data)
        result = json.loads(resp.read())
    except urllib2.HTTPError as e:
        sys.stderr.write("Error: id_data:\n")
        sys.stderr.write(id_data)
        sys.stderr.write("\n")
        sys.stderr.write(e.read())
        sys.stderr.write("\n")
        raise
    token, uri = [[c['token'], c['uri']] for c in result['challenges'] if c['type'] == "simpleHttps"][0]

    #Step 7: Ask the user to host the token on their server
    sys.stderr.write("""
STEP 2: You need to run these two commands on {} (don't stop the python command).

openssl req -new -newkey rsa:2048 -days 365 -subj "/CN=a" -nodes -x509 -keyout a.key -out a.crt
sudo python -c "import BaseHTTPServer, ssl; \\
    h = BaseHTTPServer.BaseHTTPRequestHandler; \\
    h.do_GET = lambda r: r.send_response(200) or r.end_headers() or r.wfile.write('{}'); \\
    s = BaseHTTPServer.HTTPServer(('0.0.0.0', 443), h); \\
    s.socket = ssl.wrap_socket(s.socket, keyfile='a.key', certfile='a.crt'); \\
    s.serve_forever()"

""".format(domain, token, token))

    stdout = sys.stdout
    sys.stdout = sys.stderr
    raw_input("Press Enter when you've got the python command running on your server...".format(domain))
    sys.stdout = stdout

    #Step 8: Let the CA know you're ready for the challenge
    sys.stderr.write("Requesting verification...\n")
    test_data = json.dumps({
        "header": header,
        "protected": test_nonce64,
        "payload": test_b64,
        "signature": test_sig64,
    }, sort_keys=True, indent=4)
    try:
        resp = urllib2.urlopen(uri, test_data)
        test_result = json.loads(resp.read())
    except urllib2.HTTPError as e:
        sys.stderr.write("Error: test_data:\n")
        sys.stderr.write(test_data)
        sys.stderr.write("\n")
        sys.stderr.write(e.read())
        sys.stderr.write("\n")
        raise

    #Step 9: Build the certificate request payload
    proc = subprocess.Popen(["openssl", "req", "-in", csr, "-outform", "DER"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    csr_der, err = proc.communicate()
    csr_der64 = _b64(csr_der)
    csr_authz = re.search("^([^?]+)", uri).groups()[0]
    csr_raw = json.dumps({
        "csr": csr_der64,
        "authorizations": [csr_authz],
    }, sort_keys=True, indent=4)
    csr_b64 = _b64(csr_raw)
    try:
        urllib2.urlopen(nonce_req).info()
    except urllib2.HTTPError as e:
        csr_nonce = json.dumps({
            "nonce": e.hdrs.get("replay-nonce", _b64(os.urandom(16))),
        }, sort_keys=True, indent=4)
        csr_nonce64 = _b64(csr_nonce)
    csr_file = tempfile.NamedTemporaryFile(dir=".", prefix="cert_", suffix=".json")
    csr_file.write("{}.{}".format(csr_nonce64, csr_b64))
    csr_file.flush()
    csr_file_name = os.path.basename(csr_file.name)
    csr_file_sig = tempfile.NamedTemporaryFile(dir=".", prefix="cert_", suffix=".sig")
    csr_file_sig_name = os.path.basename(csr_file_sig.name)

    #Step 10: Ask the user to sign the certificate request
    sys.stderr.write("""
STEP 3: You need to sign one more file (replace 'user.key' with your user private key).

openssl dgst -sha256 -sign user.key -out {} {}

""".format(csr_file_sig_name, csr_file_name))

    stdout = sys.stdout
    sys.stdout = sys.stderr
    raw_input("Press Enter when you've run the above command in a new terminal window...")
    sys.stdout = stdout

    #Step 11: Get the certificate signed
    sys.stderr.write("Requesting signature...\n")
    csr_file_sig.seek(0)
    csr_sig64 = _b64(csr_file_sig.read())
    csr_data = json.dumps({
        "header": header,
        "protected": csr_nonce64,
        "payload": csr_b64,
        "signature": csr_sig64,
    }, sort_keys=True, indent=4)
    try:
        resp = urllib2.urlopen("{}/new-cert".format(CA), csr_data)
        signed_der = resp.read()
    except urllib2.HTTPError as e:
        sys.stderr.write("Error: csr_data:\n")
        sys.stderr.write(csr_data)
        sys.stderr.write("\n")
        sys.stderr.write(e.read())
        sys.stderr.write("\n")
        raise

    #Step 12: Convert the signed cert from DER to PEM
    sys.stderr.write("Certificate signed!\n")
    sys.stderr.write("You can stop running the python command on your server (Ctrl+C works).\n")
    signed_der64 = base64.b64encode(signed_der)
    signed_pem = """\
-----BEGIN CERTIFICATE-----
{}
-----END CERTIFICATE-----
""".format("\n".join(textwrap.wrap(signed_der64, 64)))

    return signed_pem

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="""\
Get a SSL certificate signed by a Let's Encrypt (ACME) certificate authority and
output that signed certificate. You do NOT need to run this script on your
server and this script does not ask for your private keys. It will print out
commands that you need to run with your private key or on your server as root,
which gives you a chance to review the commands instead of trusting this script.

NOTE: YOUR ACCOUNT KEY NEEDS TO BE DIFFERENT FROM YOUR DOMAIN KEY.

Prerequisites:
* openssl
* python

Example: Generate an account keypair, a domain key and csr, and have the domain csr signed.
--------------
$ openssl genrsa 4096 > user.key
$ openssl rsa -in user.key -pubout > user.pub
$ openssl genrsa 4096 > domain.key
$ openssl req -new -sha256 -key domain.key -subj "/CN=example.com" > domain.csr
$ python sign_csr.py user.pub domain.csr > signed.crt
--------------

""")
    parser.add_argument("pubkey_path", help="path to your account public key")
    parser.add_argument("csr_path", help="path to your certificate signing request")

    args = parser.parse_args()
    signed_crt = sign_csr(args.pubkey_path, args.csr_path)
    sys.stdout.write(signed_crt)

