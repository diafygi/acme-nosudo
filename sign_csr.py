import argparse, subprocess, json, os, urllib2, sys, base64, binascii, ssl, \
    hashlib, tempfile, re, time

def sign_csr(csr):
    """Use the ACME protocol to get an ssl certificate signed by a
    certificate authority.

    :param string csr: Path to the certificate signing request.

    :returns: Signed Certificate (PEM format)
    :rtype: string

    """
    CA = "https://letsencrypt-demo.org/"
    #CA = "http://localhost:8888/"

    def _b64(b):
        "Shortcut function to go from bytes to jwt base64 string"
        return base64.urlsafe_b64encode(b).replace("=", "")

    def _a64(a):
        "Shortcut function to go from jwt base64 string to bytes"
        return base64.urlsafe_b64decode(str(a + ("=" * (len(a) % 4))))

    #Step 1: Get the domain name to be certified
    sys.stderr.write("Reading csr file...\n")
    proc = subprocess.Popen(["openssl", "req", "-in", csr, "-noout", "-text"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = proc.communicate()
    domain, pub_hex, pub_exp = re.search("\
Subject:.+? CN=([^\s,;/]+).+?\
Modulus\:\s+00:([a-f0-9\:\s]+?)\
Exponent\: ([0-9]+)\
", out, re.MULTILINE|re.DOTALL).groups()
    pub_mod = binascii.unhexlify(re.sub("(\s|:)", "", pub_hex))
    pub_mod64 = _b64(pub_mod)
    pub_exp = int(pub_exp)
    pub_exp = "{0:x}".format(pub_exp)
    pub_exp = "0{}".format(pub_exp) if len(pub_exp) % 2 else pub_exp
    pub_exp = binascii.unhexlify(pub_exp)
    pub_exp64 = _b64(pub_exp)
    sys.stderr.write("Found domain '{}'\n".format(domain))

    #Step 2: Get challenges from the CA
    sys.stderr.write("Requesting challenges...")
    data = json.dumps({
        "type": "challengeRequest",
        "identifier": domain,
    })
    resp = urllib2.urlopen(CA, data)
    result = resp.read()
    resp_json = json.loads(result)
    sessionID = resp_json['sessionID']
    nonce64 = resp_json['nonce']
    nonce = _a64(nonce64)
    challenges = resp_json['challenges']
    sys.stderr.write("Challenges received!\n")

    #Step 3: Get the dvsni challenge
    sys.stderr.write("Parsing dvsni challenge...\n")
    challenge = [c for c in challenges if c['type'] == "dvsni"][0]
    dvsni_nonce = binascii.unhexlify(challenge['nonce'])
    dvsni_r = _a64(challenge['r'])

    #Step 4: Calculate the sni code
    client_code = os.urandom(32)
    sni_code = hashlib.sha256(dvsni_r + client_code).hexdigest()
    sni = sni_code + ".acme.invalid"

    #Step 5: Generate the OpenSSL configuration for the SNI challenge
    sys.stderr.write("Generating test configuation...\n")
    proc = subprocess.Popen(["openssl", "version", "-d"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = proc.communicate()
    openssl_dir = re.search("OPENSSLDIR: \"([^\"]+)\"", out).group(1)
    openssl_cnf = open(os.path.join(openssl_dir, "openssl.cnf")).read()
    test_conf = tempfile.NamedTemporaryFile(dir=".", prefix="test_", suffix=".cnf")
    test_conf.write(openssl_cnf)
    test_conf.write("\n\n[ alt_names ]\nsubjectAltName = DNS:" + sni + "\n")
    test_conf.flush()

    #Step 5: Generate a self-signed ssl cert with the sni altname
    sys.stderr.write("Generating test key for dvsni challenge...\n")
    test_crt = tempfile.NamedTemporaryFile(dir=".", prefix="test_", suffix=".crt")
    test_crt_name = os.path.basename(test_crt.name)
    test_pem = tempfile.NamedTemporaryFile(dir=".", prefix="test_", suffix=".pem")
    test_pem_name = os.path.basename(test_pem.name)
    proc = subprocess.Popen(
        ["openssl", "req", "-new", "-newkey", "rsa:4096",
        "-days", "365", "-nodes", "-x509", "-sha256",
        "-subj", "/C=AA/ST=A/L=A/O=A/CN={}".format(domain),
        "-config", test_conf.name, "-extensions", "alt_names",
        "-keyout", test_pem.name, "-out", test_crt.name],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    proc.wait()
    sys.stderr.write("Test key generated!\n")

    #Step 6: Get ready to sign the challenge response
    msgsig_nonce = os.urandom(16)
    msgsig_nonce64 = _b64(msgsig_nonce)
    msg = msgsig_nonce + domain + nonce
    msg_file = tempfile.NamedTemporaryFile(dir=".", prefix="test_", suffix=".msg")
    msg_file_name = os.path.basename(msg_file.name)
    msg_file.write(msg)
    msg_file.flush()
    msgsig_file = tempfile.NamedTemporaryFile(dir=".", prefix="test_", suffix=".msgsig")
    msgsig_file_name = os.path.basename(msgsig_file.name)

    #Step 7: Get ready to sign the certificate request response
    dersig_nonce = os.urandom(16)
    dersig_nonce64 = _b64(dersig_nonce)
    proc = subprocess.Popen(["openssl", "req", "-in", csr, "-outform", "DER"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    der_raw, err = proc.communicate()
    der = dersig_nonce + der_raw
    der_file = tempfile.NamedTemporaryFile(dir=".", prefix="test_", suffix=".der")
    der_file_name = os.path.basename(der_file.name)
    der_file.write(der)
    der_file.flush()
    dersig_file = tempfile.NamedTemporaryFile(dir=".", prefix="test_", suffix=".dersig")
    dersig_file_name = os.path.basename(dersig_file.name)

    #Step 8: Get the user to sign the request and start the https server
    sys.stderr.write("""
====================================================
================USER ACTION REQUIRED================
====================================================

Since we don't ask for your private key or sudo access, you will need
to do some manual commands in order to get a signed certificate. Here's
what you need to do:

1. Sign some files requested by the certificate authority.
2. Copy a test key and certificate to your server.
3. Run an https server with the test key and certificate.

We've listed the commands you need to do this below. You should be able
to copy and paste them into a new terminal window.

(NOTE: Replace 'priv.key' below with your private key, if different)
(NOTE: Replace 'ubuntu' below with your sudo user, if different)

COMMANDS:
--------------------------
#Step 1: Sign the needed files
openssl dgst -sha256 -sign priv.key -out {} {}
openssl dgst -sha256 -sign priv.key -out {} {}

#Step 2: Copy the test key and certificate to your server
scp {} ubuntu@{}:{}
scp {} ubuntu@{}:{}

#Step 3: Run an https server with the test key and certificate
ssh -t ubuntu@{} "sudo python -c \\"import BaseHTTPServer, ssl; \\
  httpd = BaseHTTPServer.HTTPServer(('0.0.0.0', 443), BaseHTTPServer.BaseHTTPRequestHandler); \\
  httpd.socket = ssl.wrap_socket(httpd.socket, keyfile='{}', certfile='{}'); \\
  httpd.serve_forever()\\""
--------------------------

====================================================
====================================================
====================================================

""".format(
    msgsig_file_name, msg_file_name,
    dersig_file_name, der_file_name,
    test_pem_name, domain, test_pem_name,
    test_crt_name, domain, test_crt_name,
    domain, test_pem_name, test_crt_name))

    stdout = sys.stdout
    sys.stdout = sys.stderr
    raw_input("Press Enter when you've run the above commands in a new terminal window...")
    sys.stdout = stdout

    #Step 9: Let the CA know you are ready for the challenge
    msgsig_file.seek(0)
    msgsig_in = msgsig_file.read()
    f = open("test.sig", "wb")
    f.write(msgsig_in)
    f.close()
    msgsig64 = _b64(msgsig_in)
    sys.stderr.write("Sending challenge response...\n")
    data = json.dumps({
        "type": "authorizationRequest",
        "sessionID": sessionID,
        "nonce": nonce64,
        "signature": {
            "nonce": msgsig_nonce64,
            "alg": "RS256",
            "jwk": {
                "kty": "RSA",
                "e": pub_exp64,
                "n": pub_mod64
            },
            "sig": msgsig64
        },
        "responses": [
            {
                "type": "dvsni",
                "s": _b64(client_code)
            }
        ]
    })
    resp = urllib2.urlopen(CA, data)
    result = json.loads(resp.read())

    #Step 10: Wait for the response giving authorization
    is_done = False
    while not is_done:
        if result['type'] == "defer":
            sys.stderr.write("Deferred...\n")
            time.sleep(result.get("interval", 3))
            data = json.dumps({
                "type": "statusRequest",
                "token": result['token']
            })
            resp = urllib2.urlopen(CA, data)
            result = json.loads(resp.read())
        else:
            sys.stderr.write("Sending certificate request...\n")
            is_done = True

    #Step 11: Request the signed certificate
    proc = subprocess.Popen(["openssl", "req", "-in", csr, "-outform", "DER"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    csr_der, err = proc.communicate()
    csr_der64 = _b64(csr_der)
    dersig_file.seek(0)
    dersig = dersig_file.read()
    dersig64 = _b64(dersig)
    data = json.dumps({
        "type": "certificateRequest",
        "csr": csr_der64,
        "signature": {
            "alg": "RS256",
            "nonce": dersig_nonce64,
            "sig": dersig64,
            "jwk": {
                "kty": "RSA",
                "e": pub_exp64,
                "n": pub_mod64
            }
        }
    })
    resp = urllib2.urlopen(CA, data)
    result = json.loads(resp.read())
    sys.stderr.write("Exporting signed certificate...\n")

    #Step 12: Parse and output the signed certificate!
    crt_start = "-----BEGIN CERTIFICATE-----\n"
    crt_end = "\n-----END CERTIFICATE-----\n"
    crt64 = result['certificate']
    crt_pem = base64.b64encode(_a64(crt64))
    crt_pem = "\n".join(crt_pem[i:i+64] for i in xrange(0, len(crt_pem), 64))
    crt_pem = crt_start + crt_pem + crt_end
    for chain64 in result.get("chains", []):
        chain_pem = base64.b64encode(_a64(chain64))
        chain_pem = "\n".join(chain_pem[i:i+64] for i in xrange(0, len(chain_pem), 64))
        chain_pem = crt_start + chain_pem + crt_end
        crt_pem += chain_pem
    sys.stderr.write("Done! Your certificate is signed by the certificate authority!\n")
    return crt_pem


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="""\
Get a SSL certificate signed by a Let's Encrypt (ACME) certificate authority and
output that signed certificate. You do NOT need to run this script on your
server and this script does not ask for your private key. It will print out
commands that you need to run with your private key or on your server as root,
which gives you a chance to review the commands instead of trusting this script.

Prerequisites:
* openssl
* python

Example: Generate a key, create a csr, and have it signed.
--------------
$ openssl genrsa -out priv.key 4096
$ openssl req -new -sha256 -key priv.key -out cert.csr
$ python sign_csr.py cert.csr > signed.crt
--------------

""")
    parser.add_argument("csr_path", help="path to certificate signing request")

    args = parser.parse_args()
    signed_crt = sign_csr(args.csr_path)
    sys.stdout.write(signed_crt)

