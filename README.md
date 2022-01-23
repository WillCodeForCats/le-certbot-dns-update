# le-certbot-dns-update
DNS Update RFC2136 script for Certbot and Let's Encrypt

Use RFC2136 DNS updates with TSIG to set DNS challenge for certbot.

## Usage with certbot:
```
--manual
--preferred-challenges=dns
--manual-auth-hook '/path/to/certbot-dns-update.pl -u'
--manual-cleanup-hook '/path/to/certbot-dns-update.pl -d'
```
## Links
https://certbot.eff.org

https://github.com/WillCodeForCats/le-certbot-dns-update
