import argparse, subprocess, json, os, urllib2, sys, base64, binascii, ssl, \
    hashlib, tempfile, re, time

def sign_csr(csr):
    """Use the ACME protocol to get an ssl certificate signed by a
    certificate authority.

    :param string csr: Path to the certificate signing request.

    :returns: Signed Certificate (PEM format)
    :rtype: string

    """
    CA = "https://www.letsencrypt-demo.org/acme"
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
Subject:.*? CN=([^\s,;/]+).*?\
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
    header = {
        "alg": "RS256",
        "jwk": {
            "e": pub_exp64,
            "kty": "RSA",
            "n": pub_mod64,
        },
    }
    header_json = json.dumps(header, sort_keys=True)
    header64 = _b64(header_json)
    sys.stderr.write("Found domain '{}'\n".format(domain))

    #Step 2: Generate the payloads that need to be signed
    #registration
    reg_raw = json.dumps({
        "contact": ["mailto:webmaster@{}".format(domain)],
        "agreement": "https://www.letsencrypt-demo.org/terms",
    }, sort_keys=True)
    reg_b64 = _b64(reg_raw)
    reg_file = tempfile.NamedTemporaryFile(dir=".", prefix="letsencrypt_reg_", suffix=".json")
    reg_file.write("{}.{}".format(header64, reg_b64))
    reg_file.flush()
    reg_file_name = os.path.basename(reg_file.name)
    reg_file_sig = reg_file_name.replace(".json", ".sig")

    #identifier
    id_raw = json.dumps({"identifier": {"type": "dns", "value": domain}}, sort_keys=True)
    id_b64 = _b64(id_raw)
    id_file = tempfile.NamedTemporaryFile(dir=".", prefix="letsencrypt_id_", suffix=".json")
    id_file.write("{}.{}".format(header64, id_b64))
    id_file.flush()
    id_file_name = os.path.basename(id_file.name)
    id_file_sig = id_file_name.replace(".json", ".sig")

    #challenge
    test_path = _b64(os.urandom(16))
    test_raw = json.dumps({"type": "simpleHttps", "path": test_path}, sort_keys=True)
    test_b64 = _b64(test_raw)
    test_file = tempfile.NamedTemporaryFile(dir=".", prefix="letsencrypt_test_", suffix=".json")
    test_file.write("{}.{}".format(header64, test_b64))
    test_file.flush()
    test_file_name = os.path.basename(test_file.name)
    test_file_sig = test_file_name.replace(".json", ".sig")

    #certificate
    proc = subprocess.Popen(["openssl", "req", "-in", csr, "-outform", "DER"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    csr_der, err = proc.communicate()
    csr_der64 = _b64(csr_der)
    csr_raw = json.dumps({"csr": csr_der64}, sort_keys=True)
    csr_b64 = _b64(csr_raw)
    csr_file = tempfile.NamedTemporaryFile(dir=".", prefix="letsencrypt_csr_", suffix=".json")
    csr_file.write("{}.{}".format(header64, csr_b64))
    csr_file.flush()
    csr_file_name = os.path.basename(csr_file.name)
    csr_file_sig = csr_file_name.replace(".json", ".sig")

    #Step 3: Ask the user to sign the payloads
    sys.stderr.write("""
==================================================
================STEP 1: SIGN FILES================
==================================================

Since we don't ask for your private key or sudo access, you will need
to do some manual commands in order to get a signed certificate. Here's
the first set of commands (do them in a new terminal window).

1. Sign the four request files we've generated (commands below).

openssl dgst -sha256 -sign priv.key -out {} {}
openssl dgst -sha256 -sign priv.key -out {} {}
openssl dgst -sha256 -sign priv.key -out {} {}
openssl dgst -sha256 -sign priv.key -out {} {}

(NOTE: Replace 'priv.key' below with your private key, if different)

==================================================
==================================================
==================================================

""".format(
    reg_file_sig, reg_file_name,
    id_file_sig, id_file_name,
    test_file_sig, test_file_name,
    csr_file_sig, csr_file_name))

    stdout = sys.stdout
    sys.stdout = sys.stderr
    raw_input("Press Enter when you've run the above commands in a new terminal window...")
    sys.stdout = stdout

    #Step 4: Load the signatures
    reg_sig64 = _b64(open(reg_file_sig).read())
    id_sig64 = _b64(open(id_file_sig).read())
    test_sig64 = _b64(open(test_file_sig).read())
    csr_sig64 = _b64(open(csr_file_sig).read())

    #Step 5: Register the user
    sys.stderr.write("Registering...")
    reg_data = "{}.{}.{}".format(header64, reg_b64, reg_sig64)
    resp = urllib2.urlopen("{}/new-reg".format(CA), reg_data)
    result = json.loads(resp.read())

    #Step 6: Get simpleHttps challenge token
    sys.stderr.write("Requesting challenges...")
    id_data = "{}.{}.{}".format(header64, id_b64, id_sig64)
    resp = urllib2.urlopen("{}/new-authz".format(CA), id_data)
    result = json.loads(resp.read())
    token, uri = [[c['token'], c['uri']] for c in result['challenges'] if c['type'] == "simpleHttps"][0]

    #Step 7: Ask the user to host the token on their server
    sys.stderr.write("""
=====================================================
================STEP 2: VERIFY SERVER================
=====================================================

The certificate authority wants to verify you control the domain
by serving a random string at a specific url.

Here's the commands (RUN THESE ANYWHERE ON YOUR SERVER):
------------
#Create a temporary self-signed cert
openssl req -new -newkey rsa:2048 -days 365 -subj "/CN=a" -nodes -x509 -keyout a.key -out a.crt

#Serve the token on port 443
sudo python -c "import BaseHTTPServer, ssl; \\
  h = BaseHTTPServer.BaseHTTPRequestHandler; \\
  h.do_GET = lambda r: r.send_response(200) or r.end_headers() or r.wfile.write('{}'); \\
  s = BaseHTTPServer.HTTPServer(('0.0.0.0', 443), h); \\
  s.socket = ssl.wrap_socket(s.socket, keyfile='a.key', certfile='a.crt'); \\
  s.serve_forever()"
------------

ALTERNATIVELY:
If you are already serving content over https, you can add the
token to your server config. A request to
https://{}/.well-known/acme-challenge/{}
should return the token "{}"
as the body.
TODO: apache and nginx configs showing how to do this.

=====================================================
=====================================================
=====================================================

""".format(token, domain, test_path, token))

    stdout = sys.stdout
    sys.stdout = sys.stderr
    raw_input("Press Enter when you're serving the token on your server...")
    sys.stdout = stdout

    #Step 8: Let the CA know you're ready for the challenge
    sys.stderr.write("Requesting verification...")
    test_data = "{}.{}.{}".format(header64, test_b64, test_sig64)
    resp = urllib2.urlopen(uri, test_data)
    result = json.loads(resp.read())

    #Step 9: Wait for a little while to let the challenge pass
    sys.stderr.write("Waiting for verification...")
    time.sleep(3)

    #Step 10: Get the certificate signed
    sys.stderr.write("Requesting signature...")
    csr_data = "{}.{}.{}".format(header64, csr_b64, csr_sig64)
    try:
        resp = urllib2.urlopen("{}/new-cert".format(CA), csr_data)
        result = json.loads(resp.read())
        print "result", result
    except Exception as e:
        print "e", e
        print "e.read()", e.read()

    return "TODO"


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

