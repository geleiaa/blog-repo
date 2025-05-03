---
layout: post
title: recon for real
date: 2024-06-13
description: recon notes
categories: web recon
---

notes of [@jhaddix](https://twitter.com/Jhaddix) lives

[https://book.hacktricks.xyz/generic-methodologies-and-resources/external-recon-methodology](https://book.hacktricks.xyz/generic-methodologies-and-resources/external-recon-methodology)

{% include figure.liquid loading="eager" path="assets/img/path.png" width="500" height="500" class="img-fluid rounded z-depth-1" zoomable=true %}

> ## Assets discovery

- #### Acquisitions: empresas dentro de empresas
  - [ ] [https://www.crunchbase.com/](https://www.crunchbase.com/)
  - [ ] Owler [https://www.owler.com/](https://www.owler.com/)
  - [ ] BuiltWith [https://builtwith.com/](https://builtwith.com/)
  - [ ] Linkedin
  - [ ] Wikipedia (search for acquisitions)
  - [ ] Intelx [https://intelx.io/tools](https://intelx.io/tools)

  
  {% include figure.liquid loading="eager" path="assets/img/infodata.png" width="500" height="500" class="img-fluid rounded z-depth-1" zoomable=true %}

  - [ ] search engines

  {% include figure.liquid loading="eager" path="assets/img/searchengs.png" width="500" height="500" class="img-fluid rounded z-depth-1" zoomable=true %}


- #### Encontre o ASN (se houver) de cada empresa, isso nos dará os intervalos de IP pertencentes a cada empresa
  - [ ] [http://bgp.he.net](http://bgp.he.net)
  - [ ] [http://asnlookup.com/](http://asnlookup.com/)
  - [ ] [http://ipv4info.com/](http://ipv4info.com/)
  - [ ] [https://book.hacktricks.xyz/generic-methodologies-and-resources/external-recon-methodology#asns](https://book.hacktricks.xyz/generic-methodologies-and-resources/external-recon-methodology#asns) other asn's regions 

  - [ ] automate scan in ASNs with [asnmap](https://github.com/projectdiscovery/asnmap), [metabigor](https://github.com/j3ssie/metabigor) or [amass](https://github.com/OWASP/Amass) (vps use only)
      - ```$ echo AS394161 | asnmap -silent | naabu -silent```

      - ```$ echo AS394161 | asnmap -silent | naabu -silent -nmap-cli 'nmap -sV'```

      - ```amass intel -asn 46489```


- #### Reverse Whois and DNS permite encontrar mais infos a partir de um nome, email, domain. etc 
  - [ ] [https://centralops.net/co/](https://centralops.net/co/)
  - [ ] [https://dnsdumpster.com/](https://dnsdumpster.com/)
  - [ ] [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/)
  - [ ] [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois)
  - [ ] [https://www.reversewhois.io/](https://www.reversewhois.io/)
  - [ ] [https://www.whoxy.com/](https://www.whoxy.com/)
  - [ ] [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search)
  - [ ] Tool for automate [https://github.com/vysecurity/DomLink](https://github.com/vysecurity/DomLink)
  - [ ] ``` amass intel -d tesla.com -whois ```


- #### Reverse DNS: com intervalos de IP dos domínios (ASN's), você pode tentar realizar pesquisas reversas de DNS nesses IPs para encontrar mais domínios dentro do escopo
  - [ ] dnsrecon tool [https://github.com/darkoperator/dnsrecon](https://github.com/darkoperator/dnsrecon)
    - ```
      dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
      dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
      dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
      dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
      ```    

- #### more techiniques and resources 
  - [https://book.hacktricks.xyz/generic-methodologies-and-resources/external-recon-methodology](https://book.hacktricks.xyz/generic-methodologies-and-resources/external-recon-methodology)
  - [https://github.com/geleiaa/Reconnaissance_notes/blob/main/hakaiNotes.md](https://github.com/geleiaa/Reconnaissance_notes/blob/main/hakaiNotes.md)
  - [https://gowthams.gitbook.io/bughunter-handbook/list-of-vulnerabilities-bugs/recon-and-osint/recon](https://gowthams.gitbook.io/bughunter-handbook/list-of-vulnerabilities-bugs/recon-and-osint/recon)
  - OneLiners [https://github.com/KingOfBugbounty/KingOfBugBountyTips](https://github.com/KingOfBugbounty/KingOfBugBountyTips)


> ## Domains and SubDomains

- #### [ ] Reverse whois and dns

- #### [ ] Dorks
  - Copyright text
  - Terms of service text
  - Privacy policy text
  - Pesquise nas palavras das páginas da web que podem ser compartilhadas em diferentes sites da mesma organização. A sequência de direitos autorais pode ser um bom exemplo. Depois procure por essa string no google, em outros navegadores ou até mesmo no shodan.

  - ###### [ ] subdomain scraping

    - site:twitch.tv -www.twitch.tv or -www.sub,twitch.tv -sub.twitch.tv

    - Tools for automate [GooFuzz](https://github.com/m3n0sd0n4ld/GooFuzz) and [sd-goo](https://github.com/darklotuskdb/sd-goo)


- #### [ ] Trackers: se encontrar o mesmo ID do mesmo tracker em 2 páginas diferentes você pode supor que ambas as páginas são gerenciadas pela mesma equipe
  - [https://book.hacktricks.xyz/generic-methodologies-and-resources/external-recon-methodology#trackers](https://book.hacktricks.xyz/generic-methodologies-and-resources/external-recon-methodology#trackers)


- #### [ ] Favicon analysis
  1. [https://github.com/devanshbatham/FavFreak](https://github.com/devanshbatham/FavFreak)

  2. [https://github.com/m4ll0k/BBTz/blob/master/favihash.py](https://github.com/m4ll0k/BBTz/blob/master/favihash.py)
      - ```cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt```
        ```python3 favihash.py -f https://target/favicon.ico -t targets.txt -s```

  3. Search favicon hash on shodan 
      - ```shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'```


- #### [ ] Passive Sub Enum

- ##### certs, passivos e historical subdomain

  - [securitytrails.com](https://securitytrails.com/)
  - [subdomainfinder.c99.nl](https://subdomainfinder.c99.nl/)
  - [wayback machine](https://web.archive.org/)
  - subfinder
  - certspotter [https://sslmate.com/certspotter/](https://sslmate.com/certspotter/) (free tools)
  - ctfr (crt.sh) [https://github.com/UnaPibaGeek/ctfr](https://github.com/UnaPibaGeek/ctfr)
  - chaos.projectdiscovery.io
  - [Sudomy](https://github.com/Screetsec/Sudomy)


1. [ ] [Subfinder](https://github.com/projectdiscovery/subfinder)
      - ```subfinder -d DOMAIN -silent -all -o subfinder_output | httpx -silent -o httpx_output```
      - ```subfinder -d domain.com -silent | httpx -status```
      - ```subfinder -d domain | httpx -csp-probe -title```

2. [ ] Github-subdomains.py é um script parte do repositório de enumeração Github chamado “github-search”. Ele consultará a API do Github em busca de subdomains [https://github.com/gwen001/github-search/blob/master/github-subdomains.py](https://github.com/gwen001/github-search/blob/master/github-subdomains.py)

3. [ ] passive subdomain recon with shodan [https://github.com/incogbyte/shosubgo](https://github.com/incogbyte/shosubgo)

4. [ ] tomnomnom tool [https://github.com/tomnomnom/assetfinder](https://github.com/tomnomnom/assetfinder)

5. [ ] [theHarvester](https://github.com/laramies/theHarvester)
      - ```theHarvester -d DOMAIN -b "anubis, baidu, bing, binaryedge, bingapi, bufferoverun, censys, certspotter, crtsh, dnsdumpster, duckduckgo, fullhunt, github-code, google, hackertarget, hunter, intelx, linkedin, linkedin_links, n45ht, omnisint, otx, pentesttools, projectdiscovery, qwant, rapiddns, rocketreach, securityTrails, spyse, sublist3r, threatcrowd, threatminer, trello, twitter, urlscan, virustotal, yahoo, zoomeye"```

6. [ ] sub, cloud, js [https://github.com/nsonaniya2010/SubDomainizer](https://github.com/nsonaniya2010/SubDomainizer)

7. [ ] VHosts / Virtual Hosts: se você encontrou um endereço IP contendo uma ou várias páginas da web pertencentes a subdomínios, você pode tentar encontrar outros subdomínios nesse IP forçando nomes de domínio VHost com força bruta nesse IP.
      - [https://github.com/SpiderLabs/HostHunter](https://github.com/SpiderLabs/HostHunter)

8. [ ] CORS Brute Force: as vezes você encontrará páginas que retornam apenas o header Access-Control-Allow-Origin quando um domínio/subdomínio válido é definido no cabeçalho Origin
      - ```ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body```


- #### [ ] Shodan passive recon


{% include figure.liquid loading="eager" path="assets/img/shodanrsrc.png" width="500" height="500" class="img-fluid rounded z-depth-1" zoomable=true %}


  - passive recon [https://github.com/pirxthepilot/wtfis](https://github.com/pirxthepilot/wtfis)

  - passive recon with shodan [https://github.com/Dheerajmadhukar/karma_v2](https://github.com/Dheerajmadhukar/karma_v2)

  - smap port scan (shodan api free) [https://github.com/s0md3v/Smap](https://github.com/s0md3v/Smap)
    - ```$ smap DOMAIN or IP```



> ## Recon in Cloud based infra

cloud ips:

Amazon: [http://bit.ly/2vUSjED](http://bit.ly/2vUSjED)

Azure: [http://bit.ly/2r7rHeR](http://bit.ly/2r7rHeR)

Google Cloud: [http://bit.ly/2HAsZFm](http://bit.ly/2HAsZFm)

[https://github.com/lord-alfred/ipranges/blob/main/all/ipv4_merged.txt](https://github.com/lord-alfred/ipranges/blob/main/all/ipv4_merged.txt) (cloud providers ips)

[http://kaeferjaeger.gay/](http://kaeferjaeger.gay/) (cloud providers ips)

- How To Scan AWS's Entire IP Range to Recon SSL Certificates [https://www.daehee.com/blog/scan-aws-ip-ssl-certificates](https://www.daehee.com/blog/scan-aws-ip-ssl-certificates)


- #### [ ] Tools for automate
  - [ ] [https://github.com/initstring/cloud_enum](https://github.com/initstring/cloud_enum)
  - [ ] [https://github.com/jordanpotti/CloudScraper](https://github.com/jordanpotti/CloudScraper)
  - [ ] [https://github.com/projectdiscovery/cloudlist](https://github.com/projectdiscovery/cloudlist)
  - [ ] [https://github.com/sa7mon/S3Scanner](https://github.com/sa7mon/S3Scanner)


- #### [ ] cert transparecy in cloud ips

  - [https://github.com/UnaPibaGeek/ctfr](https://github.com/UnaPibaGeek/ctfr)

  - [https://github.com/cheetz/sslScrape](https://github.com/cheetz/sslScrape)

  - cert transparecy in cloud ips/domains [https://github.com/g0ldencybersec/cloudrecon](https://github.com/g0ldencybersec/cloudrecon)
    - parse cloudrecon tool data collected:
      1. ```$ grep -F '.DOMAIN.COM' domainfile_DB.txt | awk -F '[][]''{print $2}' | sed 's##\n#g' "DOMAIN.COM" | sort -fu | cut -d ',' -f1 | sort -u```

      2. ```$ grep -F '.DOMAIN.COM' domainfile_DB.txt | awk -F '[][]''{print $2}' | sed 's##\n#g' | sort -fu | cut -d ',' -f1 | sort -u```


- #### [ ] resolve ips to domains via ssl cert

  - [https://github.com/hakluke/hakip2host](https://github.com/hakluke/hakip2host)
    - ```$ prips 173.0.84.0/24 | ./hakip2host```

- #### [ ] CDN checker [https://github.com/projectdiscovery/cdncheck](https://github.com/projectdiscovery/cdncheck)


> ## Github

- #### [ ] _cs.github_
 
  - [https://github.blog/2021-12-08-improving-github-code-search/](https://github.blog/2021-12-08-improving-github-code-search/)

- #### [ ] Git dorker

  - [https://github.com/obheda12/GitDorker](https://github.com/obheda12/GitDorker)


- #### [ ] git exposed
 
- [ ] ``` $ echo domain.com | subfinder -silent | xargs -I@ sh -c 'goop @ -f' ```

- [ ] [https://github.com/arthaud/git-dumper](https://github.com/arthaud/git-dumper)
 
- [ ] [https://github.com/nyancrimew/goop](https://github.com/nyancrimew/goop)

- #### [ ] github search

- [ ] [https://gist.github.com/jhaddix/1fb7ab2409ab579178d2a79959909b33](https://gist.github.com/jhaddix/1fb7ab2409ab579178d2a79959909b33)

- [ ] [https://github.com/gwen001](https://github.com/gwen001)



> ## After sub enum

- [ ] after subdomain enum verify if domains is active/online
- [ ] crawling, params discovery, vulns check
- #### [ ] Screeshotting: analysis all screeshot and priorize domains to test (eyewitness, aquatone, httpscreenshot)

  - [https://github.com/michenriksen/aquatone](https://github.com/michenriksen/aquatone)
  - [https://github.com/breenmachine/httpscreenshot](https://github.com/breenmachine/httpscreenshot)
  - [https://github.com/RedSiege/EyeWitness](https://github.com/RedSiege/EyeWitness)


> ## [ ] Pré-Manual Testing and Automation

#### [ ] Test Layers

  - [ ] Open Ports and Services
  - [ ] Web Hosting Software
  - [ ] Application Framework
  - [ ] Application Custon Code or COTS
  - [ ] Application Libraries (usually javascript)


#### [ ] Tech-Profiling

  - [ ] webanalyze cli tool (wappalyzer)

#### [ ] Find cve's and misconfigs

  - [ ] nuclei scan for vulns
  - [ ] gofingerprint (Tanner Barnes)
  - [ ] Sn1per (@xer0dayz)
  - [ ] Intrigue Core (jcran)
  - [ ] Vulners (Burp ext)
  - [ ] Jaeles Scanner (j3ssi3jjj)
  - [ ] retire.js

#### [ ] Service Scanning

  - [ ] [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray)

#### [ ] Port Scan

  - [ ] use passive methods first, later if you care use active methods


> ### Content/Parameter/URL Discovery

  - [ ] Based on tech
  - [ ] COTS/PAID/OSS (danielmiessler/Source2URL)
  - [ ] Custom (github.com/0xDexter0us/Scavenger)
  - [ ] Historical (echo domain.com | gau | wordlistgen | sort -u)
  - [ ] Recursive (Tip: if you found a 401 dont stop, keep going and go deep)
  - [ ] Mobile APIs
  - [ ] Change Detection
  - [ ] Technologies Tips (web servers and frameworks)

- ##### [ ] waybackmachine content discovery
  - [ ] [https://github.com/mhmdiaa/chronos](https://github.com/mhmdiaa/chronos)
  - [ ] [https://github.com/daudmalik06/ReconCat](https://github.com/daudmalik06/ReconCat)
  - [ ] [https://github.com/tomnomnom/waybackurls](https://github.com/tomnomnom/waybackurls)

- #### Tools

  - [ ] [https://github.com/jaeles-project/gospider](https://github.com/jaeles-project/gospider)
  - [ ] [https://github.com/projectdiscovery/katana](https://github.com/projectdiscovery/katana)
  - [ ] [https://github.com/s0md3v/Arjun](https://github.com/s0md3v/Arjun) ``` $ arjun -u url ```
  - [ ] hakrawler [https://github.com/hakluke/hakrawler](https://github.com/hakluke/hakrawler)
  - [ ] gau [https://github.com/lc/gau](https://github.com/lc/gau)
  - [ ] [https://github.com/tomnomnom/unfurl](https://github.com/tomnomnom/unfurl)
  - [ ] [https://github.com/GerbenJavado/LinkFinder](https://github.com/GerbenJavado/LinkFinder)
  - [ ] turbo intruder
  - [ ] Gobuster
  - [ ] feroxbuster
  - [ ] ParamSpider
  - [ ] Parht
  - [ ] kxss
  - [ ] wfuzz
  - [ ] ffuf ```ffuf -u http://api.com.br/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt -p 20 -t 1 -c -v -o ffuf_output```
  - [ ] dirsearch



- [ ] ``` $ cat domains.txt | httpx -status | gau ```

- [ ] ``` $ cat domains.txt | httpx -status -ports 80,443,8080 -path /admin ``` 

- [ ] ``` $ subfinder -d domain.com -silent | aquatone ``` 

- [ ] ``` $ cat targets | ./feroxbuster --stdin --silent -s 200 301 302 --redirects -x js | fff -s 200 -o js-files ```

- [ ] ``` $ echo domain | waybackurls | unfurl paths ```

- [ ] ``` $ echo domain | waybackurls | unfurl keys ```

- [ ] ``` $ echo domains | waybackurls | gf xss | hakcheckurl ```

- [ ] ``` $ echo domains | subfinder -silent | httpx -silent | katana -silent -d 10 | unfurl keys | uro ```


{% include figure.liquid loading="eager" path="assets/img/contdisclists.png" width="500" height="500" class="img-fluid rounded z-depth-1" zoomable=true %}


> ## [ ] Application Analysis

- #### [ ] Big Questions
  - [ ] how does the app pass data?
  - [ ] how and where does the app talk about users? 
    - [ ] where = cookies, api calls; how = uid, email,username, uuid
  - [ ] does the site have multi-users or user levels?
    - [ ] App designed for multiple customers
    - [ ] App has multiple users levels
      - [ ] Admin (cms/framework)
      - [ ] account admin
      - [ ] account user 
      - [ ] acount view
      - [ ] unauthenticated functionality
  - [ ] does the site have a unique threat model? (test PII data)
  - [ ] has there been past security research & vulns?
  - [ ] how does the app handle tries of xss, csrf, injection (sql, template, ...)

- #### [ ] spidering
  - [ ] zaproxy or burp
  - [ ] hakcrawler and gospider

- #### [ ] javascript analysis
  - [ ] find some things hardcoded
  - [ ] SecretFinder [https://github.com/m4ll0k/SecretFinder](https://github.com/m4ll0k/SecretFinder)
  - [ ] linkfinder
  - [ ] xnLinkFinder (@xnl-h4ck3r)
  - [ ] GAP burp ext
  - [ ] minified or obfuscated js still needs to be assessed manually

- #### [ ] hot areas
  - [ ] "Places" inside the application where bad things can normally happen
  - [ ] Or things i want to look at, that may indicate interesting places to explore from a hacker PoV

- #### [ ] parameter analysis
  - [ ] priorize parameters that were vulnerable to certain vulns classes...
  - [ ] gf tomnomnom [https://github.com/tomnomnom/gf](https://github.com/tomnomnom/gf)
  - [ ] jhaddix/sus_params
  - [ ] Dlafox [https://github.com/hahwul/dalfox](https://github.com/hahwul/dalfox)
  - [ ] Gxss [https://github.com/KathanP19/Gxss](https://github.com/KathanP19/Gxss)
  - [ ] Airixss [https://github.com/ferreiraklet/airixss](https://github.com/ferreiraklet/airixss)
  - ```cat url_with_params | uro | gf xss```
  - ```cat url_with_params | uro | gf xss | httpx -t 1 -rlm 4 | qsreplace '"><svg onload=confirm(1)' | airixss -c 1 -p "confirm(1)"```
  - ```cat url_with_params | httpx -t 1 -rlm 4 | Gxss -c 1 -p GELEIA -v -o gxss_out```
  - ```cat wayback_output | Gxss -c 100 -p GELEIA | dalfox pipe --skip-bav --silence```
  


{% include figure.liquid loading="eager" path="assets/img/hotareasmap.png" width="500" height="500" class="img-fluid rounded z-depth-1" zoomable=true %}


- Adding more constantly...
