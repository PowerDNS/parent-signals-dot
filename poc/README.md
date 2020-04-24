with https://github.com/PowerDNS/hash-slinger/commit/b55fd06ee2cd2d3d05fb55bf77bbd580ca31ebd0 :
```
 ./tlsa -4 --insecure --selector 1 --mtype 0 a.ns.facebook.com -p 853  | grep CDNSKEY
Warning: query data is not secure.
a.ns.facebook.com. IN CDNSKEY 0 3 225 MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAny429nLK2z9RebEg/WTXonp7at/Kreg6ngT5yA7/BrHPL1v+LTcvKERo9UE4hVGpKxHTjvMWti6pbmVus8cfbrsSGh+cYR/pV/eINITeVF2DL7xN2IggTDSUxH9ph4uJWRX5Cq32nm8hVZhRslNg+j0XVan8kzgr59C94xzK/nFUTSKuLYy3R7pyKBQYUmCXeR9cJCod2Atg/x0Mh7nozcXe9SaiectoQty9slg90NP2+myWAlAdsrZ2cixqYvEmPtlhcnAj/33rctpdLt+jI2K3MyhHgRRyxWMNzebkHTUZ2X2zNSIP7TVe1kaPfAuO7oP+jr5CzfvZZYwd4NDSwwIDAQAB
$ ./tlsa -4 --insecure --selector 1 --mtype 0 a.ns.facebook.com -p 853 | sed s/CDNS/DNS/ | sed s/a.ns.facebook.com/facebook.com/ | grep DNS | ldns-key2ds -2 -n -f /dev/stdin
Warning: query data is not secure.
facebook.com.	3600	IN	DS	62637 225 2 ddbfb9887bef31f61617d84fe2ba21f917eccc1790e74505ecd48071a52200ea
```

then:
```
$ python3 -mvenv .venv
$ .venv/bin/pip install -r requirements.txt
$ .venv/bin/python test.py 225 facebook.com a.ns.facebook.com | tail -1
facebook.com IN DS x 225 2 ddbfb9887bef31f61617d84fe2ba21f917eccc1790e74505ecd48071a52200ea
```

If test.py had looked up, and found, that DS record, it could confidently send queries over the TLS connection it has just established!

(I randomly picked algorithm number 225).

In Go:
```
$ go run ./test.go
Hello, playground
Hash: ddbfb9887bef31f61617d84fe2ba21f917eccc1790e74505ecd48071a52200ea
```

In shell (Bash): (just to show that the SPKI is entered into the DNSKEY unprocessed, the only mild processing happens when making or matching the DS)
```
$ echo 'facebook.com CDNSKEY 0 3 225' $(echo -n | openssl s_client -connect a.ns.facebook.com:853 | openssl x509 -noout -pubkey  | grep -v \-)
facebook.com CDNSKEY 0 3 225 MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAny429nLK2z9RebEg/WTX onp7at/Kreg6ngT5yA7/BrHPL1v+LTcvKERo9UE4hVGpKxHTjvMWti6pbmVus8cf brsSGh+cYR/pV/eINITeVF2DL7xN2IggTDSUxH9ph4uJWRX5Cq32nm8hVZhRslNg +j0XVan8kzgr59C94xzK/nFUTSKuLYy3R7pyKBQYUmCXeR9cJCod2Atg/x0Mh7no zcXe9SaiectoQty9slg90NP2+myWAlAdsrZ2cixqYvEmPtlhcnAj/33rctpdLt+j I2K3MyhHgRRyxWMNzebkHTUZ2X2zNSIP7TVe1kaPfAuO7oP+jr5CzfvZZYwd4NDS wwIDAQAB
```
