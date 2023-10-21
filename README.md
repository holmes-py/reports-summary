#### Links to refer for more information:
>https://github.com/reddelexc/hackerone-reports
>https://www.bugbountyhunter.com/disclosed/
>https://hackerone.com/hacktivity/cwe_discovery?id=cwe-284

All of these are taken from reddelexc’s repo which indexes all top reports on h1, I am straight up taking those, reading them one by one, and adding summaries here.   

### DoS attacks Reports  

•	[DoS on PayPal via web cache poisoning](https://hackerone.com/reports/622122) to PayPal
-	Added `any-header: burpcollaborator.net` leads to site cache on that parameter getting poisoned and leads to DoS. 

•	[profile-picture name parameter with large value lead to DoS for other users and programs on the platform](https://hackerone.com/reports/764434) to HackerOne 
-	Any place or parameter with upload image have no limit of name size length, so when long long file names are used, it leads to DoS.

•	[Denial of service to WP-JSON API by cache poisoning the CORS allow origin header](https://hackerone.com/reports/591302) to Automattic
-	Edge case with wordpress and automattic, not reproducible 

•	[Denial of service via cache poisoning](https://hackerone.com/reports/409370) to HackerOne
-	Super fun, a simple `curl -H 'X-Forwarded-Port: 123' https://www.hackerone.com/index.php?dontpoisoneveryone=1` would poison the cache and next time anyone tried to visit the same parameter, it would redirect to website:123/blahblahblah, if done on the main website, we can do it to `curl -H 'X-Forwarded-Host: www.hackerone.com:123' https://www.hackerone.com/index.php?dontpoisoneveryone=1` poison the cache and redirect everything to our website. 

•	[Ability to DOS any organization's SSO and open up the door to account takeovers](https://hackerone.com/reports/976603) to Grammarly
-	Edge case with  Grammarly’s implementation of SSO, but check if any org allows to make a business account,  and come back on this to read. lol

•	[Uploading large payload on domain instructions causes server-side DoS](https://hackerone.com/reports/887321) to HackerOne 
-	eh,  as the title, just spam large payloads to any upload enabled graphQL endpoint.

•	[Node disk DOS by writing to container /etc/hosts](https://hackerone.com/reports/867699) to Kubernetes 
-	For kubes specifc misconfiguration 

•	[xmlrpc.php FILE IS enable it will used for Bruteforce attack and Denial of Service(DoS)](https://hackerone.com/reports/752073) to Nord Security
-	Some good exploit if you have xmlrpc.php enabled/available on the target.

•	[DoS on the Issue page by exploiting Mermaid.](https://hackerone.com/reports/470067) to GitLab
-	Mermaid, another edge case for gitlab’s older versions, beyond 2019. 
•	[character limitation bypass can lead to DoS on Twitter App and 500 Internal Server Error](https://hackerone.com/reports/819088) to X (Formerly Twitter) -  $0
-	Overloaded a twitter endpoint that creates ‘moments’ with double quotes, and this resulted in 500 error, on android and website. The primary reason for this was the 500 error, without that, they won’t pay anything. This is also out of scope on twitter now. 

•	[Permanent DoS with one click.](https://hackerone.com/reports/975827) to Automattic -  $0
-	Create 2 accounts, send a msg from accountA to accountB, then delete accountA, and try to see the message from accountB, results in a crash.

•	[a very long name in hey.com can prevent anyone from accessing their contacts and probably can cause denial of service](https://hackerone.com/reports/1018037) to Basecamp -  $1000
-	While account creation, changed the name to a very long string, cause the app to slow down when anyone visits the profile. Results in DoS.

•	[HTML Injection in Swing can disclose netNTLM hash or cause DoS](https://hackerone.com/reports/1054382) to PortSwigger Web Security - $1000
-	Eh

•	[ActiveStorage throws exception when using whitespace as filename, may lead to denial of service of multiple pages](https://hackerone.com/reports/713407) to HackerOne - $0
-	Super cool, add `+` or `%0d%0a` , or `%20` to a filename when uploading, like profile pic, this will lead to application wide DoS wherever the profile is displayed.

•	[Denial of Service via Hyperlinks in Posts](https://hackerone.com/reports/1077136) to Slack - $1500
-	- 
•	[Cache Poisoning DoS on downloads.exodus.com](https://hackerone.com/reports/1173153) to Exodus 
-	-   

•	[Attacker with an Old account might still be able to DoS ctf.hacker101.com by sending a Crafted request ](https://hackerone.com/reports/861170) to HackerOne 
-	-   

•	[Denial of Service | twitter.com & mobile.twitter.com](https://hackerone.com/reports/903740) to X (Formerly Twitter) 
-	-   

•	[Denial Of Service (Out Of Memory) on Updating Bounty Table [Urgent]](https://hackerone.com/reports/1043372) to HackerOne 
-	-   

•	[DoS attack via comment on Issue](https://hackerone.com/reports/557154) to GitLab 
-	-   

•	[[mijn.werkenbijdefensie.nl] Denial of service occurs due to lack of email length confirmation](https://hackerone.com/reports/920926) to Radancy 
-	-   

•	[https://themes.shopify.com::: Host header web cache poisoning lead to DoS](https://hackerone.com/reports/1096609) to Shopify 
-	-   

•	[DoS of https://nordvpn.com/ via CVE-2018-6389 exploitation](https://hackerone.com/reports/752010) to Nord Security 
-	-   

•	[Cache Poisoning DoS on updates.rockstargames.com](https://hackerone.com/reports/1219038) to Rockstar Games 
-	-   

•	[Cache poisoning Denial of Service affecting assets.gitlab-static.net](https://hackerone.com/reports/1160407) to GitLab 
-	-   

•	[[www.werkenbijbakertilly.nl] Denial of service due to incorrect server return can result in total denial of service.](https://hackerone.com/reports/892615) to Radancy 
-	-   

•	[Denial of Service  [Chrome]](https://hackerone.com/reports/921286) to X (Formerly Twitter) 
-	-   

•	[Authorization issue in Google G Suite allows DoS through HTTP redirect](https://hackerone.com/reports/191196) to Uber 
-	-   

•	[DoS: type confusion in mrb_no_method_error](https://hackerone.com/reports/181871) to shopify-scripts 
-	-   

•	[Web Cache Poisoning leads to XSS and DoS](https://hackerone.com/reports/1621540) to Glassdoor 
-	-   

•	[[api.tumblr.com] Denial of Service by cookies manipulation](https://hackerone.com/reports/1005421) to Automattic 
-	-   

•	[DoS through PeerExplorer](https://hackerone.com/reports/363636) to IOVLabs 
-	-   

•	[DoS via markdown API from unauthenticated user](https://hackerone.com/reports/1619604) to GitHub 
-	-   

•	[Potential DoS vulnerability in Django in multipart parser](https://hackerone.com/reports/1904097) to Internet Bug Bounty 
-	-   

•	[DOS in stream filters](https://hackerone.com/reports/505278) to Internet Bug Bounty 
-	-   

•	[Arbitrary file creation with semi-controlled content (leads to DoS, EoP and others) at Steam Windows Client](https://hackerone.com/reports/682774) to Valve 
-	-   

•	[Google  Maps API key stored as plain text leading to DOS and financial damage](https://hackerone.com/reports/1093667) to Zenly 
-	-   

•	[DoS attacks utilizing camo.stream.highwebmedia.com](https://hackerone.com/reports/507525) to Chaturbate 
-	-   

•	[Memory Leak in OCUtil.dll library in Desktop client can lead to DoS](https://hackerone.com/reports/588562) to Nextcloud 
-	-   

•	[Hash-Collision Denial-of-Service Vulnerability in Markdown Parser](https://hackerone.com/reports/1341957) to Reddit 
-	-   

•	[DOS via cache poisoning on [developer.mozilla.org]](https://hackerone.com/reports/1976449) to Mozilla Core Services 
-	-   

•	[iOS group chat denial of service](https://hackerone.com/reports/1701642) to LINE 
-	-   

•	[Application DOS via specially crafted payload on 3d.cs.money](https://hackerone.com/reports/993582) to CS Money 
-	-   

•	[%0A (New line) and limitness URL leads to DoS at all system [Main adress (https://www.acronis.com/)]](https://hackerone.com/reports/1382448) to Acronis 
-	-   

•	[Regular expression denial of service in ActiveRecord's PostgreSQL Money type](https://hackerone.com/reports/1023899) to Ruby on Rails 
-	-   

•	[Remote denial of service in  HyperLedger Fabric](https://hackerone.com/reports/1604951) to Hyperledger 
-	-   

•	[Chrome Extension is vulnerable to the self-DOS issues in case it process the security.txt with a big size](https://hackerone.com/reports/290955) to Ed 
-	-   

•	[Cookie poisoning leads to DOS and Privacy Violation](https://hackerone.com/reports/1067809) to CS Money 
-	-   

•	[CryptoNote: remote node DoS](https://hackerone.com/reports/506595) to Monero 
-	-   

•	[Use after free vulnerability in mruby Array#to_h causing DOS possible RCE](https://hackerone.com/reports/181321) to shopify-scripts 
-	-   

•	[DoS on the Direct Messages](https://hackerone.com/reports/746003) to Slack 
-	-   

•	[No redirect_uri in the db for web-internal clientKey leads to one-click DoS on gitter.im](https://hackerone.com/reports/702987) to GitLab 
-	-   

•	[Remote Server Restart Lead to Denial of Service by only one Request.](https://hackerone.com/reports/114698) to Keybase 
-	-   

•	[Fastify denial-of-service vulnerability with large JSON payloads](https://hackerone.com/reports/303632) to Node.js third-party modules 
-	-   

•	[cookie injection allow dos attack to periscope.tv](https://hackerone.com/reports/583819) to X (Formerly Twitter) 
-	-   

•	[DOS attack by consuming all CPU and using all available memory](https://hackerone.com/reports/479144) to Tron Foundation 
-	-   

•	[ICQ Android APP remote DoS](https://hackerone.com/reports/892510) to Mail.ru 
-	-   

•	[JSON RPC methods for debugging enabled by default allow DoS](https://hackerone.com/reports/324021) to IOVLabs 
-	-   

•	[Cache poisoning DoS to various TTS assets](https://hackerone.com/reports/728664) to GSA Bounty 
-	-   

•	[DOS via issue preview](https://hackerone.com/reports/1543718) to GitLab 
-	-   

•	[xmlrpc.php FILE IS enable it will used for bruteforce attack and denial of service](https://hackerone.com/reports/325040) to LocalTapiola 
-	-   

•	[Cookie injection leads to complete DoS over whole domain *.mackeeper.com. Injection point accountstage.mackeeper.com/](https://hackerone.com/reports/861521) to Clario 
-	-   

•	[DoS through cache poisoning using invalid HTTP parameters](https://hackerone.com/reports/326639) to Greenhouse.io 
-	-   

•	[Single User DOS by Poisoning Cookie via Get Parameter](https://hackerone.com/reports/416966) to Pornhub 
-	-   

•	[Insecure Processing of XML leads to Denial of Service through Billion Laughs Attack](https://hackerone.com/reports/754117) to Razer 
-	-   

•	[Bypass of request line length limit to DoS via cache poisoning](https://hackerone.com/reports/350847) to Greenhouse.io 
-	-   

•	[XMLRPC, Enabling XPSA and Bruteforce and DOS + A file disclosing installer-logs.](https://hackerone.com/reports/865875) to MTN Group 
-	-   

•	[DoS of LINE client for Android via message containing multiple unicode characters (0x0e & 0x0f)](https://hackerone.com/reports/1058383) to LINE 
-	-   

•	[DOS validator nodes of blockchain to block external connections](https://hackerone.com/reports/1695472) to Hyperledger 
-	-   

•	[Pixel Flood Attack leads to Application level DoS](https://hackerone.com/reports/970760) to CS Money 
-	-   

•	[scripts loader (denial of service) vulnerability](https://hackerone.com/reports/690330) to MariaDB 
-	-   

•	[Comments Denial of Service in socialclub.rockstargames.com](https://hackerone.com/reports/214370) to Rockstar Games 
-	-   

•	[Variant of CVE-2013-0269 (Denial of Service and Unsafe Object Creation Vulnerability in JSON)](https://hackerone.com/reports/706934) to Ruby 
-	-   

•	[xmlrpc.php And /wp-json/wp/v2/users FILE IS enable it will used for bruteforce attack and denial of service](https://hackerone.com/reports/1147449) to Sifchain 
-	-   

•	[Denial of Service by requesting to reset a password](https://hackerone.com/reports/812754) to Nextcloud 
-	-   

•	[lack of input validation that can lead Denial of Service (DOS)](https://hackerone.com/reports/768677) to X (Formerly Twitter) 
-	-   

•	[Permanent Denial of Service ](https://hackerone.com/reports/5534) to MS-DOS 
-	-   

•	[Specially constructed multi-part requests cause multi-second response times; vulnerable to DoS](https://hackerone.com/reports/431561) to Ruby on Rails 
-	-   

•	[DOS via move_issue](https://hackerone.com/reports/1543584) to GitLab 
-	-   

•	[Race condition on the Federalist API endpoints can lead to the Denial of Service attack](https://hackerone.com/reports/249319) to GSA Bounty 
-	-   

•	[WEBrick::HTTPAuth::DigestAuth authentication is vulnerable to regular expression denial of service (ReDoS)](https://hackerone.com/reports/661722) to Ruby 
-	-   

•	[Possible denial of service when entering a loooong password](https://hackerone.com/reports/952349) to Nextcloud 
-	-   

•	[Server-side denial of service via large payload sent to wiki.cs.money/graphql](https://hackerone.com/reports/993005) to CS Money 
-	-   

•	[CVE-2023-23916: HTTP multi-header compression denial of service](https://hackerone.com/reports/1826048) to curl 
-	-   

•	[[Java] CWE-755: Query to detect Local Android DoS caused by NFE](https://hackerone.com/reports/1061211) to GitHub Security Lab 
-	-   

•	[Single user DOS on selectedLanguage -cookie (yrityspalvelu.lahitapiola.fi)](https://hackerone.com/reports/201723) to LocalTapiola 
-	-   

•	[DoS for HTTP/2 connections by crafted requests (CVE-2018-1333)](https://hackerone.com/reports/384839) to Internet Bug Bounty 
-	-   

•	[xmlrpc.php file is enable it will used for (Denial of Service) and bruteforce attack](https://hackerone.com/reports/747829) to BlockDev Sp. Z o.o 
-	-   

•	[Attacker may be able to bounce enough emails which suspend HackerOne's SES service and cause a DoS of HackerOne's email service](https://hackerone.com/reports/823915) to HackerOne 
-	-   

•	[DoS via Playbook ](https://hackerone.com/reports/1685979) to Mattermost 
-	-   

•	[xmlrpc.php FILE IS enabled it will used for Bruteforce attack and Denial of Service(DoS)](https://hackerone.com/reports/1086850) to BlockDev Sp. Z o.o 
-	-   

•	[Cookie-based client-side denial-of-service to all of the Lähitapiola domains](https://hackerone.com/reports/129001) to LocalTapiola 
-	-   

•	[Application-level DoS on image's "size" parameter.](https://hackerone.com/reports/247700) to Gratipay 
-	-   

•	[Resource Consumption DOS on Edgemax v1.10.6](https://hackerone.com/reports/406614) to Ubiquiti Inc. 
-	-   

•	[DoS of https://blog.yelp.com/ and other WP instances via CVE-2018-6389](https://hackerone.com/reports/753491) to Yelp 
-	-   

•	[xmlrpc.php FILE IS enable it will used for Bruteforce attack and Denial of Service(DoS)](https://hackerone.com/reports/1622867) to Top Echelon Software 
-	-   

•	[Null target_class DoS](https://hackerone.com/reports/183405) to shopify-scripts 
-	-   

•	[Chained vulnerabilities create DOS attack against users on desafio5estrelas.com](https://hackerone.com/reports/624645) to Uber 
-	-   

•	[DoS via large console messages](https://hackerone.com/reports/1243724) to Mattermost 
-	-   

•	[Denial of Service with Cookie Bomb](https://hackerone.com/reports/777984) to Nord Security 
-	-   

•	[Web Cache Poisoning leading to DoS](https://hackerone.com/reports/1346618) to U.S. General Services Administration 
-	-   

•	[CVE-2022-35252: control code in cookie denial of service](https://hackerone.com/reports/1613943) to curl 
-	-   

•	[PNG compression DoS](https://hackerone.com/reports/454) to HackerOne 
-	-   

•	[Possible denial of service when entering a loooong password](https://hackerone.com/reports/840598) to Nextcloud 
-	-   

•	[No Rate Limiting on https://██████/██████████/accounts/password/reset/ endpoint leads to Denial of Service](https://hackerone.com/reports/862681) to U.S. Dept Of Defense 
-	-   

•	[Cookie Bombing cause DOS -  businesses.uber.com](https://hackerone.com/reports/847493) to Uber 
-	-   

•	[User input validation can lead to DOS](https://hackerone.com/reports/767458) to X (Formerly Twitter) 
-	-   

•	[Pre-auth Denial-of-Service in Dovecot RPA implementation](https://hackerone.com/reports/866605) to Open-Xchange 
-	-   

•	[Insufficient limitation of web page title  leads to DoS against ICQ for Android](https://hackerone.com/reports/801372) to Mail.ru 
-	-   

•	[Content length restriction bypass can lead to DOS by reading large files on gip.rocks](https://hackerone.com/reports/203388) to Gratipay 
-	-   

•	[`memjs` allocates and stores buffers on typed input, resulting in DoS and uninitialized memory usage](https://hackerone.com/reports/319809) to Node.js third-party modules 
-	-   

•	[Application level denial of service due to shutting down the server ](https://hackerone.com/reports/627376) to Node.js third-party modules 
-	-   

•	[Denial Of Service in Strapi Framework using argument injection](https://hackerone.com/reports/768574) to Node.js third-party modules 
-	-   

•	[Permanent DOS for new users!](https://hackerone.com/reports/1057484) to Stripo Inc 
-	-   

•	[[mtn.com.af] Multiple vulnerabilities allow to Application level DoS](https://hackerone.com/reports/946578) to MTN Group 
-	-   

•	[Remote denial of service in HyperLedger Fabric](https://hackerone.com/reports/1635854) to Hyperledger 
-	-   

•	[The parameter in the POST query allows to control size of returned page which in turn can lead to the potential DOS attack](https://hackerone.com/reports/300391) to LocalTapiola 
-	-   

•	[DOS: out of memory from gif through upload api](https://hackerone.com/reports/1620170) to Mattermost 
-	-   

•	[Denial of service via cache poisoning on https://www.data.gov/](https://hackerone.com/reports/942629) to GSA Bounty 
-	-   

•	[Denial of service due to invalid memory access in mrb_ary_concat](https://hackerone.com/reports/184712) to shopify-scripts 
-	-   

•	[Rack CVE-2022-30122: Denial of Service Vulnerability in Rack Multipart Parsing](https://hackerone.com/reports/1627159) to Internet Bug Bounty 
-	-   

•	[Single User DOS on SelectedLocale -cookie (verkkopalvelu.tapiola.fi)](https://hackerone.com/reports/212508) to LocalTapiola 
-	-   

•	[Single user DOS on selectedLanuage -cookie at (verkkopalvelu.tapiola.fi)](https://hackerone.com/reports/212523) to LocalTapiola 
-	-   

•	[Denial of Service through set_preference.json](https://hackerone.com/reports/166682) to Keybase 
-	-   

•	[Fix for self-DoS in Security-txt Chrome Extension.](https://hackerone.com/reports/299460) to Ed 
-	-   

•	[XML hash collision DoS vulnerability in Python's xml.etree module](https://hackerone.com/reports/412673) to Internet Bug Bounty 
-	-   

•	[DoS for remote nodes using Slow Loris attack](https://hackerone.com/reports/416494) to Monero 
-	-   

•	[Cisco ASA Denial of Service & Path Traversal (CVE-2018-0296)](https://hackerone.com/reports/378698) to ok.ru 
-	-   

•	[Multiple HTTP/2 DOS Issues](https://hackerone.com/reports/589739) to Node.js 
-	-   

•	[load scripts DOS vulnerability](https://hackerone.com/reports/694467) to OLX 
-	-   

•	[xmlrpc.php FILE IS enable which enables attacker to XSPA Brute-force and even Denial of Service(DOS), in https://████/xmlrpc.php](https://hackerone.com/reports/884756) to U.S. Dept Of Defense 
-	-   

•	[Permanent DoS at https://happy.tools/ when inviting a user](https://hackerone.com/reports/1041173) to Automattic 
-	-   

•	[Denial of Service in mruby due to null pointer dereference](https://hackerone.com/reports/181232) to shopify-scripts 
-	-   

•	[CVE-2022-32206: HTTP compression denial of service](https://hackerone.com/reports/1614330) to Internet Bug Bounty 
-	-   

•	[potential denial of service attack via the locale parameter](https://hackerone.com/reports/1746098) to Internet Bug Bounty 
-	-   

•	[CVE-2023-25692: Apache Airflow Google Provider: Google Cloud Sql Provider Denial Of Service and Remote Command Execution](https://hackerone.com/reports/1895316) to Internet Bug Bounty 
-	-   

•	[Denial of Service by resource exhaustion CWE-400 due to unfinished HTTP/1.1 requests](https://hackerone.com/reports/868834) to Node.js 
-	-   

•	[DoS in Brave browser for iOS](https://hackerone.com/reports/357665) to Brave Software 
-	-   

•	[Proxy service crash DoS](https://hackerone.com/reports/13652) to Factlink 
-	-   

•	[Возможность провести DoS атаку от имени vk.com сервера](https://hackerone.com/reports/183352) to VK.com 
-	-   

•	[CVE-2017-8779 exploit on open rpcbind port could lead to remote DoS](https://hackerone.com/reports/791893) to Endless Group 
-	-   

•	[scripts loader DOS vulnerability](https://hackerone.com/reports/690338) to FormAssembly 
-	-   

•	[Cache Posioning leading to denial of service at `█████████` - Bypass fix from report #1198434	](https://hackerone.com/reports/1322732) to U.S. Dept Of Defense 
-	-   

•	[CVE-2022-35252: control code in cookie denial of service](https://hackerone.com/reports/1686935) to Internet Bug Bounty 
-	-   

•	[Lack of Packet Sanitation in Goflow Results in Multiple DoS Attack Vectors and Bugs](https://hackerone.com/reports/1636320) to Cloudflare Public Bug Bounty 
-	-   

•	[SSRF / Local file enumeration / DoS due to improper handling of certain file formats by ffmpeg](https://hackerone.com/reports/115978) to Imgur 
-	-   

•	[Malformed SHA512 ticket DoS (CVE-2016-6302)](https://hackerone.com/reports/221787) to Internet Bug Bounty 
-	-   

•	[Denial of Service in Action Pack Exception Handling](https://hackerone.com/reports/42797) to Ruby on Rails 
-	-   

•	[`http-proxy-agent` passes unsanitized options to Buffer(arg), resulting in DoS and uninitialized memory leak](https://hackerone.com/reports/321631) to Node.js third-party modules 
-	-   

•	[DoS of www.lahitapiolarahoitus.fi via CVE-2018-6389 exploitation](https://hackerone.com/reports/335177) to LocalTapiola 
-	-   

•	[Client DoS due to large DH parameter (CVE-2018-0732)](https://hackerone.com/reports/364964) to Internet Bug Bounty 
-	-   

•	[Algorithmic complexity vulnerability in ZXCVBN leads to remote denial of service attack](https://hackerone.com/reports/542897) to Dropbox 
-	-   

•	[[cloudron-surfer] Denial of Service via LDAP Injection](https://hackerone.com/reports/906959) to Node.js third-party modules 
-	-   

•	[Denial of Service in anti_ransomware_service.exe via logs files](https://hackerone.com/reports/858603) to Acronis 
-	-   

•	[Application level DOS at Login Page ( Accepts Long Password )](https://hackerone.com/reports/1168804) to Reddit 
-	-   

•	[DoS at ████████ (CVE-2018-6389)](https://hackerone.com/reports/1861569) to U.S. Dept Of Defense 
-	-   

•	[ WordPress application vulnerable to DoS attack via wp-cron.php](https://hackerone.com/reports/1888723) to U.S. Dept Of Defense 
-	-   

•	[Range constructor type confusion DoS](https://hackerone.com/reports/181910) to shopify-scripts 
-	-   

•	[CVE-2022-32205: Set-Cookie denial of service](https://hackerone.com/reports/1614328) to Internet Bug Bounty 
-	-   

•	[WordPress Authentication Denial of Service](https://hackerone.com/reports/163307) to Instacart 
-	-   

•	[[DOS] denial of service using code snippet on brave browser](https://hackerone.com/reports/181558) to Brave Software 
-	-   

•	[ DoS vulnerability in mod_auth_digest CVE-2016-2161](https://hackerone.com/reports/194065) to Internet Bug Bounty 
-	-   

•	[WordPress core  - Denial of Service via Cross Site Request Forgery](https://hackerone.com/reports/153093) to WordPress 
-	-   

•	[`https-proxy-agent` passes unsanitized options to Buffer(arg), resulting in DoS and uninitialized memory leak](https://hackerone.com/reports/319532) to Node.js third-party modules 
-	-   

•	[Lodash "difference" (possibly others) Function Denial of Service Through Unvalidated Input](https://hackerone.com/reports/670779) to Node.js third-party modules 
-	-   

•	[HTTP/2 Denial of Service Vulnerability](https://hackerone.com/reports/335533) to Node.js 
-	-   

•	[DoS for client-go jsonpath func](https://hackerone.com/reports/882923) to Kubernetes 
-	-   

•	[SQL Injection or Denial of Service due to a Prototype Pollution](https://hackerone.com/reports/869574) to Node.js third-party modules 
-	-   

•	[Camera adoption DoS - UniFi Protect](https://hackerone.com/reports/1008579) to Ubiquiti Inc. 
-	-   

•	[Ruby - Regular Expression Denial of Service Vulnerability of Date Parsing Methods](https://hackerone.com/reports/1404789) to Internet Bug Bounty 
-	-   

•	[Regular Expression Denial of Service vulnerability](https://hackerone.com/reports/1538157) to Reddit 
-	-   

•	[ruby DoS https://www.mruby.science](https://hackerone.com/reports/180695) to shopify-scripts 
-	-   

•	[Denial of Service any Report](https://hackerone.com/reports/118663) to HackerOne 
-	-   

•	[DOS Report  FILE html inside \<code\> in markdown](https://hackerone.com/reports/127827) to HackerOne 
-	-   

•	[Denial of service attack on Brave Browser.](https://hackerone.com/reports/176066) to Brave Software 
-	-   

•	[[tor] control connection pre-auth DoS (infinite loop) with --enable-bufferevents](https://hackerone.com/reports/113424) to Tor 
-	-   

•	[Missing back-end user input validation can lead to DOS flaw](https://hackerone.com/reports/361337) to Liberapay 
-	-   

•	[Remote P2P DoS](https://hackerone.com/reports/592200) to Monero 
-	-   

•	[monerod JSON RPC server remote DoS](https://hackerone.com/reports/1511843) to Monero 
-	-   

•	[DoS via Automatic Response Message](https://hackerone.com/reports/1680241) to Mattermost 
-	-   

•	[DoS at █████(CVE-2018-6389)](https://hackerone.com/reports/1887996) to U.S. Dept Of Defense 
-	-   

•	[Thumbor misconfiguration at blogapi.uber.com can lead to DoS](https://hackerone.com/reports/787240) to Uber 
-	-   

•	[[CVE-2023-22799] Possible ReDoS based DoS vulnerability in GlobalID](https://hackerone.com/reports/2012135) to Internet Bug Bounty 
-	-   

•	[Fastify uses allErrors: true ajv configuration by default which is susceptible to DoS](https://hackerone.com/reports/903521) to Node.js third-party modules 
-	-   

•	[help.nextcloud.com: Known DoS condition (null pointer deref) in Nginx running](https://hackerone.com/reports/145409) to Nextcloud 
-	-   

•	[Filename enumeration && DoS](https://hackerone.com/reports/174524) to Nextcloud 
-	-   

•	[No Password Length Restriction leads to Denial of Service](https://hackerone.com/reports/223854) to Weblate 
-	-   

•	[Abuse of Api that causes spamming users and possible DOS due to missing rate limit on contact form](https://hackerone.com/reports/223542) to Weblate 
-	-   

•	[Denial of service in libxml2, using malicious lzma file to consume available system memory](https://hackerone.com/reports/270059) to Internet Bug Bounty 
-	-   

•	[Denial of Service: nghttp2 use of uninitialized pointer](https://hackerone.com/reports/335608) to Node.js 
-	-   

•	[Application level DoS via xmlrpc.php ](https://hackerone.com/reports/787179) to U.S. Dept Of Defense 
-	-   

•	[DoS for GCSArtifact.RealAll](https://hackerone.com/reports/833856) to Kubernetes 
-	-   

•	[DoS due to improper input validation can break the admin access into the user data will disallow him from editing that user's data.](https://hackerone.com/reports/1147611) to Nextcloud 
-	-   

•	[Slowvote and Countdown can cause Denial of Service due to recursive inclusion](https://hackerone.com/reports/1563142) to Phabricator 
-	-   

•	[CVE-2022-32206: HTTP compression denial of service](https://hackerone.com/reports/1570651) to curl 
-	-   

•	[CVE-2022-32205: Set-Cookie denial of service](https://hackerone.com/reports/1569946) to curl 
-	-   

•	[DoS via lua_read_body() [zhbug_httpd_94]](https://hackerone.com/reports/1596252) to Internet Bug Bounty 
-	-   

•	[HTTP multi-header compression denial of service](https://hackerone.com/reports/1886139) to Internet Bug Bounty 
-	-   

•	[Arbitrary command execution in MS-DOS](https://hackerone.com/reports/5499) to MS-DOS 
-	-   

•	[Potential denial of service in hackerone.com/\<program\>/reward_settings](https://hackerone.com/reports/63865) to HackerOne 
-	-   

•	[Denial of service (segfault) due to null pointer dereference in mrb_obj_instance_eval](https://hackerone.com/reports/202582) to shopify-scripts 
-	-   

•	[doc.owncloud.com: CVE-2015-5477 BIND9 TKEY Vulnerability + Exploit (Denial of Service)](https://hackerone.com/reports/217381) to ownCloud 
-	-   

•	[ci.nextcloud.com: CVE-2015-5477 BIND9 TKEY Vulnerability + Exploit (Denial of Service)](https://hackerone.com/reports/237860) to Nextcloud 
-	-   

•	[Ruby 2.3.x and 2.2.x still bundle DoS vulnerable verision of libYAML](https://hackerone.com/reports/235842) to Ruby 
-	-   

•	[pngcrush double-free/segfault could result in DoS (CVE-2015-7700)](https://hackerone.com/reports/93546) to Internet Bug Bounty 
-	-   

•	[CVE-2017-5969: libxml2 when used in recover mode, allows remote attackers to cause a denial of service (NULL pointer dereference)](https://hackerone.com/reports/262665) to Internet Bug Bounty 
-	-   

•	[Dos  https://iandunn.name/ via CVE-2018-6389 exploitation](https://hackerone.com/reports/770508) to Ian Dunn 
-	-   

•	[load scripts DOS vulnerability](https://hackerone.com/reports/826238) to BlockDev Sp. Z o.o 
-	-   

•	[HTTP2 'unknownProtocol' cause Denial of Service by resource exhaustion](https://hackerone.com/reports/1043360) to Node.js 
-	-   

•	[Cache Posioning leading do Denial of Service on `www.█████████`](https://hackerone.com/reports/1198434) to U.S. Dept Of Defense 
-	-   

•	[Instance Page DOS  within Organization on TikTok Ads](https://hackerone.com/reports/1478930) to TikTok 
-	-   

•	[Denial of Service vulnerability in curl when parsing MQTT server response](https://hackerone.com/reports/1521610) to curl 
-	-   

•	[DoS of  https://research.adobe.com/ via CVE-2018-6389 exploitation](https://hackerone.com/reports/1511628) to Adobe 
-	-   

•	[Regular Expression Denial of Service in Headers](https://hackerone.com/reports/1784449) to Node.js 
-	-   

•	[Possible DOS in app with crashing `exceptions_app`](https://hackerone.com/reports/1300802) to Ruby on Rails 
-	-   

•	[Possible DoS Vulnerability in Multipart MIME parsing in rack](https://hackerone.com/reports/1954937) to Internet Bug Bounty 
-	-   

•	[[CVE-2022-44570] Possible Denial of Service Vulnerability in Rack’s Range header parsing](https://hackerone.com/reports/2012121) to Internet Bug Bounty 
-	-   

•	[[CVE-2023-22796] Possible ReDoS based DoS vulnerability in Active Support’s underscore](https://hackerone.com/reports/2012131) to Internet Bug Bounty 
-	-   

•	[[CVE-2022-44572] Possible Denial of Service Vulnerability in Rack’s RFC2183 boundary parsing](https://hackerone.com/reports/2012125) to Internet Bug Bounty 
-	-   

•	[[CVE-2022-44571] Possible Denial of Service Vulnerability in Rack Content-Disposition parsing](https://hackerone.com/reports/2012122) to Internet Bug Bounty 
-	-   

•	[DNS Max Responses for DOS](https://hackerone.com/reports/1033107) to Node.js 
-	-   

•	[Denial of Service](https://hackerone.com/reports/17785) to HackerOne 
-	-   

•	[DoS Attack in Controller Lookup Code](https://hackerone.com/reports/83962) to Ruby on Rails 
-	-   

•	[Possible  SQL injection can cause denial of service attack](https://hackerone.com/reports/123660) to Dropbox 
-	-   

•	[Denial of service in report view.](https://hackerone.com/reports/140720) to HackerOne 
-	-   

•	[Denial of service in account statistics endpoint](https://hackerone.com/reports/136221) to Mapbox 
-	-   

•	[Denial of service attack(window object) on brave browser](https://hackerone.com/reports/176197) to Brave Software 
-	-   

•	[Denial of service (segfault) due to null pointer dereference in mrb_vm_exec](https://hackerone.com/reports/202584) to shopify-scripts 
-	-   

•	[Abuse of Api that causes spamming users and possible DOS due to missing rate limit](https://hackerone.com/reports/223557) to Weblate 
-	-   

•	[Regular Expression Denial of Service (ReDoS)](https://hackerone.com/reports/317548) to Node.js third-party modules 
-	-   

•	[Server side includes in https://lgtm-com.pentesting.semmle.net/internal_api/v0.2/savePublicInformation leads to 500 server error and  D-DOS](https://hackerone.com/reports/413655) to Semmle 
-	-   

•	[Node.js HTTP/2 Large Settings Frame DoS](https://hackerone.com/reports/446662) to Node.js 
-	-   

•	[Improper Input Validation allows an attacker to "double spend" or "respend", violating the integrity of the message command history or causing DoS](https://hackerone.com/reports/981357) to Agoric 
-	-   

•	[DoS attack against the client when entering a long password](https://hackerone.com/reports/949712) to Nextcloud 
-	-   

•	[API Server DoS (crash?) if many large resources (~1MB each) are concurrently/repeatedly sent to an external Validating WebHook endpoint](https://hackerone.com/reports/1096907) to Kubernetes 
-	-   

•	[[play.mtn.co.za] Application level DoS via xmlrpc.php](https://hackerone.com/reports/925519) to MTN Group 
-	-   

•	[1-click DOS in fastify-static via directly passing user's input to new URL() of NodeJS without try/catch](https://hackerone.com/reports/1361804) to Fastify 
-	-   

•	[Self-DoS due to template injection via email field in password reset form on access.acronis.com](https://hackerone.com/reports/1265344) to Acronis 
-	-   

•	[moderate: mod_deflate denial of service](https://hackerone.com/reports/20861) to Internet Bug Bounty 
-	-   

•	[Potential denial of service in hackerone.com/teams/new](https://hackerone.com/reports/13748) to HackerOne 
-	-   

•	[History Disclosure of MS-Dos](https://hackerone.com/reports/5549) to MS-DOS 
-	-   

•	[Apache Range Header Denial of Service Attack (Confirmed PoC)](https://hackerone.com/reports/88904) to ownCloud 
-	-   

•	[CrashPlan Backup is Vulnerable Allowing to a DoS Attack Against Uber's Backups to ```backup.uber.com```](https://hackerone.com/reports/131560) to Uber 
-	-   

•	[xmlrpc.php FILE IS enable it can be used for conducting a Bruteforce attack and Denial of Service(DoS)](https://hackerone.com/reports/769716) to Ian Dunn 
-	-   

•	["Self" DOS with large deployment and scaling](https://hackerone.com/reports/831654) to Kubernetes 
-	-   

•	[Denial of Service when entring an Array in email at seetings](https://hackerone.com/reports/961997) to Nextcloud 
-	-   

•	[[meemo-app] Denial of Service via LDAP Injection](https://hackerone.com/reports/907311) to Node.js third-party modules 
-	-   

•	[[json-bigint] DoS via `__proto__` assignment](https://hackerone.com/reports/916430) to Node.js third-party modules 
-	-   

•	[[http-live-simulator] Application-level DoS](https://hackerone.com/reports/764725) to Node.js third-party modules 
-	-   

•	[DRb denial of service vulnerability](https://hackerone.com/reports/898614) to Ruby 
-	-   

•	[Possibility of DoS attack at https://sifchain.finance// via CVE-2018-6389 exploitation](https://hackerone.com/reports/1186985) to Sifchain 
-	-   

•	[curl "globbing" can lead to denial of service attacks](https://hackerone.com/reports/1572120) to curl 
-	-   

•	[Inadequate input validation on API endpoint leading to self denial of service and increased system load.](https://hackerone.com/reports/90912) to IRCCloud 
-	-   

•	[Dashboard panel embedded onto itself causes a denial of service](https://hackerone.com/reports/85011) to Phabricator 
-	-   

•	[owncloud.com: CVE-2015-5477 BIND9 TKEY Vulnerability + Exploit (Denial of Service)](https://hackerone.com/reports/89097) to ownCloud 
-	-   

•	[DOS in browser using window.print() function](https://hackerone.com/reports/176364) to Brave Software 
-	-   

•	[Denial of service(POP UP Recursion) on Brave browser](https://hackerone.com/reports/179248) to Brave Software 
-	-   

•	[Possibility of DOS Through logging System](https://hackerone.com/reports/242489) to Quora 
-	-   

•	[Media parsing in canvas is at least vulnerable to Denial of Service through multiple vulnerabilities](https://hackerone.com/reports/315037) to Node.js third-party modules 
-	-   

•	[DoS of https://blog.makerdao.com/ via CVE-2018-6389](https://hackerone.com/reports/777274) to BlockDev Sp. Z o.o 
-	-   

•	[A specifically designed sieve script can cause a DoS in lib-sieve during sieve script compilation via NULL pointer dereference](https://hackerone.com/reports/965774) to Open-Xchange 
-	-   

•	[No Password Length Restriction leads to Denial of Service](https://hackerone.com/reports/1243009) to Reddit 
-	-   
