#Let's Encrypt Without Sudo

**WARNING: THE LET'S ENCRYPT CERTIFICATE AUTHORITY IS NOT YET READY! ANY
CERTIFICATES YOU HAVE SIGNED NOW WILL STILL RETURN BROWSER WARNINGS!**

The [Let's Encrypt](https://letsencrypt.org/) initiative is a fantastic program
that is going to offer **free** https certificates! However, the one catch is
that you need to use their command program to get a free certificate. You have
to run it on your your server as root, and it tries to edit your apache/nginx
config files.

I love the Let's Encrypt devs dearly, but there's no way I'm going to trust
their script to run on my server as root and be able to edit my server configs.
I'd just like the free ssl certificate, please.

So I made a script that does that. You generate your private key and certificate
signing request (CSR) like normal, then run `sign_csr.py` with your CSR to get
it signed. The script goes through the [ACME protocol](https://github.com/letsencrypt/acme-spec)
with the Let's Encrypt certificate authority and outputs the signed certificate
to stdout.

This script doesn't know or ask for your private key, and it doesn't need to be
run on your server. There are some parts of the ACME protocol that require your
private key and access to your server. For those parts, this script prints out
very minimal commands for you to run to complete the requirements. There is only
one command that needs to be run as root on your server and it is a very simple
python https server that you can inspect for yourself before you run it.

###Donate

If this script is useful to you, please donate to the EFF. I don't work there,
but they do fantastic work.

[https://eff.org/donate/](https://eff.org/donate/)

###Prerequisites

* openssl
* python

You will also need to transfer the test key and certificate to your server
temporarily. The command printed out uses `scp` for that, but you can use any
secure transfer program.

###Example Use

**Commands (without output)**
```sh
#Generate a private key
openssl genrsa -out priv.key 4096

#Generate a CSR
openssl req -new -sha256 -key priv.key -out cert.csr

#Download the script in this repo
wget https://raw.githubusercontent.com/diafygi/letsencrypt-nosudo/master/sign_csr.py

#Get Let's Encrypt to sign the CSR
python sign_csr.py cert.csr > signed.crt

#Output the CSR so you can see it
cat signed.crt
```

**Commands (with full output)**
```sh
user@hostname:~$ openssl genrsa -out priv.key 4096
Generating RSA private key, 4096 bit long modulus
....................................................................++
...........................................................................++
e is 65537 (0x10001)
user@hostname:~$ openssl req -new -sha256 -key priv.key -out cert.csr
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:US
State or Province Name (full name) [Some-State]:California
Locality Name (eg, city) []:Oakland
Organization Name (eg, company) [Internet Widgits Pty Ltd]:Daylightpirates
Organizational Unit Name (eg, section) []:
Common Name (e.g. server FQDN or YOUR name) []:letsencrypt.daylightpirates.org
Email Address []:info@daylightpirates.org

Please enter the following 'extra' attributes
to be sent with your certificate request
A challenge password []:
An optional company name []:
user@hostname:~$ wget https://raw.githubusercontent.com/diafygi/letsencrypt-nosudo/master/sign_csr.py
--2015-01-18 21:43:22--  https://raw.githubusercontent.com/diafygi/letsencrypt-nosudo/master/sign_csr.py
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 199.27.79.133
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|199.27.79.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 11057 (11K) [text/plain]
Saving to: ‘sign_csr.py’

100%[==================================================================>] 11,057      --.-K/s   in 0.06s

2015-01-18 21:43:22 (172 KB/s) - ‘sign_csr.py’ saved [11057/11057]

user@hostname:~$ python sign_csr.py cert.csr > signed.crt
Reading csr file...
Found domain 'letsencrypt.daylightpirates.org'
Requesting challenges...Challenges received!
Parsing dvsni challenge...
Generating test configuation...
Generating test key for dvsni challenge...
Test key generated!

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
openssl dgst -sha256 -sign priv.key -out test_XhYOdY.msgsig test_vuK3N0.msg
openssl dgst -sha256 -sign priv.key -out test_Y5jK3k.dersig test_dQe_Zk.der

#Step 2: Copy the test key and certificate to your server
scp test_j3Lumf.pem ubuntu@letsencrypt.daylightpirates.org:test_j3Lumf.pem
scp test_RDBEK7.crt ubuntu@letsencrypt.daylightpirates.org:test_RDBEK7.crt

#Step 3: Run an https server with the test key and certificate
ssh -t ubuntu@letsencrypt.daylightpirates.org "sudo python -c \"import BaseHTTPServer, ssl; \
  httpd = BaseHTTPServer.HTTPServer(('0.0.0.0', 443), BaseHTTPServer.BaseHTTPRequestHandler); \
  httpd.socket = ssl.wrap_socket(httpd.socket, keyfile='test_j3Lumf.pem', certfile='test_RDBEK7.crt'); \
  httpd.serve_forever()\""
--------------------------

====================================================
====================================================
====================================================

Press Enter when you've run the above commands in a new terminal window...
Sending challenge response...
Deferred...
Sending certificate request...
Exporting signed certificate...
Done! Your certificate is signed by the certificate authority!
user@hostname:~$ cat signed.crt
-----BEGIN CERTIFICATE-----
MIIEEjCCAvqgAwIBAgIENL8QdDANBgkqhkiG9w0BAQUFADAPMQ0wCwYDVQQKEwRB
Q01FMB4XDTE1MDExOTA0NDkxNFoXDTE2MDExOTA0NDkxNFowKjEoMCYGA1UEAxMf
bGV0c2VuY3J5cHQuZGF5bGlnaHRwaXJhdGVzLm9yZzCCAiIwDQYJKoZIhvcNAQEB
BQADggIPADCCAgoCggIBALDUa5ZczCKfYJQ6VZgUv0hELX2ZhU5DMYYlfGByu9KJ
myUEsU07Tcw/vsN8g8X1wYoCtm8j/H3aT0wxN5VcUXfgVPCZBp5uD0KzdZKgRiRR
Vwp0PKi1IQkrCi1ZBAQUlkCyVzsl0yjSkyf+c9aqljzPUf0/vK7HK/HJMds3wak7
go/Z1FJD7ba8JAZStpnRvzTHfAW3vVnJ9cwoKloMl6eCs3+ICfXlA/mx0F5QG6EI
BYgOH2VyJ9ji584vM1dqc3eR2AdVuCPFCPf6O8EQ5UHx0zr15IdQ0GZIC11WTW+v
S0h7PUvbar9rJCHQAWIrvqxpHZKhCM/Nf3TIl9NTXtdJYQd4QlBJ+4WSCJCm3nx8
UdeT8yQkYJSz0y0nSbtF05h+Ly/KvtJy4APblRF+IO2pZ2g9iCVk2e29hfYo7ps5
mIy8eG3ibGWif1MeZN+lJfeDx5bu/kcjr/mUVrXHyxnPjG/nNxBDE/ff714NfHQ0
TIPA2leR5LQQGtyLD3F6HPCpmgcJfS5sy/XfAFdixCBTDzvFUgnjFQiMOljSicL2
VmF+3s+K/u61IafjqpivuPwzdO21l3gCOrKgdxlT6trNavhe000d2mIZrv/brXse
sClkTikGcREIfgwtDX3p1ckrMmkbyawgwLDLIPb0gNfBCWXpiAu+scY5ZkYOlg8J
AgMBAAGjWzBZMAkGA1UdEwQCMAAwCwYDVR0PBAQDAgWgMBMGA1UdJQQMMAoGCCsG
AQUFBwMBMCoGA1UdEQQjMCGCH2xldHNlbmNyeXB0LmRheWxpZ2h0cGlyYXRlcy5v
cmcwDQYJKoZIhvcNAQEFBQADggEBAFNXALi2n6s7zcfz97da3rts1dd8OAJ62GMV
idT68mDx1u3CwgFBLYmhUfnUYY2AKL1vbWJ25s9eeFdJEbVzlllE6MvPcqZ/j3Iz
Nqvb/oAqGEXEBxir1d1t2M5TQgLFymOUBSDuPWzwNK0O9kGS4Di9vIlADKYgBSPQ
KxuZ0uDlVkhXKOYjPtcNJh7xlvBR90UC/l1r73L8GW2cyXdKvYy+E0Cg3NrZ3ptZ
LR/qXdhLTL8P5beEGZei8H8p4nX2e/TvIbXsSDnAQDWRmzRTTuJtS0/VGNaB4HOW
vU193yL7w7n/bMVCw5FO/1t/Ba1xMRxWjPkSaOAk7fVjOjo6M70=
-----END CERTIFICATE-----
user@hostname:~$ 
```

**Manual Commands** (the stuff the script asked you to do in a 2nd terminal)
```sh
user@hostname:~$ #Step 1: Sign the needed files
user@hostname:~$ openssl dgst -sha256 -sign priv.key -out test_XhYOdY.msgsig test_vuK3N0.msg
user@hostname:~$ openssl dgst -sha256 -sign priv.key -out test_Y5jK3k.dersig test_dQe_Zk.der
user@hostname:~$ 
user@hostname:~$ #Step 2: Copy the test key and certificate to your server
user@hostname:~$ scp test_j3Lumf.pem ubuntu@letsencrypt.daylightpirates.org:test_j3Lumf.pem
test_j3Lumf.pem                                                                  100% 3272     3.2KB/s   00:00
user@hostname:~$ scp test_RDBEK7.crt ubuntu@letsencrypt.daylightpirates.org:test_RDBEK7.crt
test_RDBEK7.crt                                                                  100% 1996     2.0KB/s   00:00
user@hostname:~$ 
user@hostname:~$ #Step 3: Run an https server with the test key and certificate
user@hostname:~$ ssh -t ubuntu@letsencrypt.daylightpirates.org "sudo python -c \"import BaseHTTPServer, ssl; \
>   httpd = BaseHTTPServer.HTTPServer(('0.0.0.0', 443), BaseHTTPServer.BaseHTTPRequestHandler); \
>   httpd.socket = ssl.wrap_socket(httpd.socket, keyfile='test_j3Lumf.pem', certfile='test_RDBEK7.crt'); \
>   httpd.serve_forever()\""

########################################################
## Wait until sign_csr.py is done before killing this ##
########################################################

^CTraceback (most recent call last):
  File "<string>", line 1, in <module>
  File "/usr/lib/python2.7/SocketServer.py", line 236, in serve_forever
    poll_interval)
  File "/usr/lib/python2.7/SocketServer.py", line 155, in _eintr_retry
    return func(*args)
KeyboardInterrupt
Connection to letsencrypt.daylightpirates.org closed.
user@hostname:~$ 
```


###How to use the signed certificate

The signed https certificate that is output by this script can be used along
with your private key to run an https server. You just security transfer (using
`scp` or similar) the private key and signed certificate to your server, then
include them in the https settings in your web server's configuration. Here's an
example on how to configure an nginx server:

```nginx
server {
    listen 443;
    server_name letsencrypt.daylightpirates.org;
    ssl on;
    ssl_certificate signed.crt;
    ssl_certificate_key priv.key;
    ssl_session_timeout 5m;
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
    ssl_ciphers EECDH+aRSA+AES256:EDH+aRSA+AES256:EECDH+aRSA+AES128:EDH+aRSA+AES128;
    ssl_session_cache shared:SSL:50m;
    ssl_prefer_server_ciphers on;

    location / {
        return 200 'Let\'s Encrypt Example: https://github.com/diafygi/letsencrypt-nosudo';
        add_header Content-Type text/plain;
    }
}
```

###Demo

Here's a website that is using a certificate signed using `sign_csr.py`:

[https://letsencrypt.daylightpirates.org/](https://letsencrypt.daylightpirates.org/)

###Feedback/Contributing

I'd love to receive feedback, issues, and pull requests to make this script
better. The script itself, `sign_csr.py`, is less than 300 lines of code, so
feel free to read through it! I tried to comment things well and make it crystal
clear what it's doing.

For example, it currently can't do any ACME challenges besides dvsni. Maybe
someone could do a pull request to add more challenge compatibility? Also, it
currently can't revoke certificates, and I don't want to include that in the
`sign_csr.py` script. Perhaps there should also be a `revoke_crt.py` script?


