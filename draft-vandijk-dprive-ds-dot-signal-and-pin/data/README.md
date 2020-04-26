This directory holds example data used in the document.

1. `openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 3650 -nodes -subj '/CN=ns.example.com'` (we did this and stored it here for you, making the steps in the document easy to reproduce)
2. `cat cert.pem key.pem > server.pem`
3. (`sudo`) `openssl s_server -port 853`

Then make `ns.example.com` point at this machine.
Now you can follow along with the steps in the Example section.