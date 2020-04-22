with https://github.com/PowerDNS/hash-slinger/commit/b55fd06ee2cd2d3d05fb55bf77bbd580ca31ebd0 :
```
$ ./tlsa -4 --insecure --selector 1 --mtype 0 a.ns.facebook.com -p 853 | sed s/CDNS/DNS/ | sed s/a.ns.facebook.com/facebook.com/ | grep DNS | ldns-key2ds -2 -n -f /dev/stdin
Warning: query data is not secure.
facebook.com.	3600	IN	DS	62637 225 2 ddbfb9887bef31f61617d84fe2ba21f917eccc1790e74505ecd48071a52200ea
```

then:
```
$ python3 -mvenv .venv
$.venv/bin/pip install -r requirements.txt
$ .venv/bin/python test.py  | tail -1
ddbfb9887bef31f61617d84fe2ba21f917eccc1790e74505ecd48071a52200ea
```

If test.py had looked up, and found, that DS record, it could confidently send queries over the TLS connection it has just established!
