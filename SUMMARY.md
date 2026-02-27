# Table of contents

* [🚀 Introduction](README.md)

<!--
* [🌱 Fundamentals](fundamentals/README.md)
  * [GCP](fundamentals/gcp/README.md)
    * [Networking](fundamentals/gcp/Networking.md)

* [🛜 WiFi Penetration Testing](wifi-penetration-testing/README.md)
  * [IEEE 802.11](wifi-penetration-testing/802.11.md)
  * [WiFi Interfcaes](wifi-penetration-testing/wifi-interfaces.md)
  * [WEP](wifi-penetration-testing/WEP.md)
  * [WPS](wifi-penetration-testing/WPS.md)
  * [WPA](wifi-penetration-testing/WPA.md)
  * [WiFi Attacks](wifi-penetration-testing/attacks.md)
-->

* [🔍 Recon & Initial Access](initial-access/README.md)
  <!--* [OSINT](initial-access/osint.md)-->
  * [Scanning using Nmap](initial-access/nmap.md)
  * [Attacking Common Services](initial-access/attacking-services.md)
  <!--*  [Phishing](initial-access/phishing.md) -->

* [📉 Privilege Escalation](priv-esc/README.md)
  * [Linux](priv-esc/linux.md)
  * [Windows](priv-esc/windows.md)

* [🪟 Active Directory Penetration Testing](active-directory-penetration-testing/README.md)

  * [🚪 Breaching the Domain](active-directory-penetration-testing/breaching-the-domain/README.md)
    * [LLMNR Poisoning](active-directory-penetration-testing/breaching-the-domain/llmnr-poisoning.md)
    * [Password Spraying](active-directory-penetration-testing/breaching-the-domain/password-spraying.md)

  * [🌐 Domain Enumeration](active-directory-penetration-testing/domain-enumeration/README.md)
    * [From Linux](active-directory-penetration-testing/domain-enumeration/domain-enumeration-linux.md)
    * [From Windows](active-directory-penetration-testing/domain-enumeration/domain-enumeration-windows.md)
    * [Living Off the Land](active-directory-penetration-testing/domain-enumeration/living-off-the-land.md)

  * [🎭 Kerberos Attacks](active-directory-penetration-testing/kerberos-attacks/README.md)
    * [AS-REPRoasting](active-directory-penetration-testing/kerberos-attacks/asreproasting.md)
    * [Kerberoasting](active-directory-penetration-testing/kerberos-attacks/Kerberoasting.md)
    * [Triage](active-directory-penetration-testing/kerberos-attacks/kerberos-triage.md)
    * [Unconstrained Delegation](active-directory-penetration-testing/kerberos-attacks/unconstrained-delegation.md)
    * [Constrained Delegation](active-directory-penetration-testing/kerberos-attacks/constrained-delegation.md)
    * [RBCD](active-directory-penetration-testing/kerberos-attacks/rbcd.md)
    * [Ticket Abuse](active-directory-penetration-testing/kerberos-attacks/tickets.md)

  * [📜 ACL & Trust Exploitation](active-directory-penetration-testing/acl-and-trust-exploitation/README.md)
    * [ACL Abuse](active-directory-penetration-testing/acl-and-trust-exploitation/acl-abuse.md)
    * [Cross-Domain Trusts Abuse](active-directory-penetration-testing/acl-and-trust-exploitation/domain-trust-abuse.md)
    * [Cross-Forest Trusts Abuse](active-directory-penetration-testing/acl-and-trust-exploitation/cross-forest-trust-abuse.md)

  * [🛡️ Mitigation & Detection](active-directory-penetration-testing/mitigation-and-detection/mitigation-and-detection.md)

  * [⚒️ Hardening Active Directory](active-directory-penetration-testing/mitigation-and-detection/hardening.md)

* [🕸️ Web Penetration Testing](web-app-penetration-testing/README.md)

  * [🔍 Reconnaissance](web-app-penetration-testing/recon/reconnaissance.md)
    * [Passive Recon](web-app-penetration-testing/recon/passive-reconnaissance.md)
    * [Active Recon](web-app-penetration-testing/recon/active-reconnaissance.md)
    * [API Attacks](web-app-penetration-testing/recon/api.md)

  * [🔴 Attacks](web-app-penetration-testing/attacks/README.md)
    * [HTTP Verb Tampering](web-app-penetration-testing/attacks/http-verb-tampering.md)
    * [CRLF Injection](web-app-penetration-testing/attacks/crlf-injection.md)
    * [Information Disclosure](web-app-penetration-testing/attacks/info-disclosure.md)
    * [Authentication Bypass](web-app-penetration-testing/attacks/README.md)
    * [Login Bruteforcing](web-app-penetration-testing/attacks/login-bruteforcing.md)
    * [OAuth Attacks](web-app-penetration-testing/attacks/oauth.md)
    * [SAML Attacks](web-app-penetration-testing/attacks/saml.md)
    * [JWT Attacks](web-app-penetration-testing/attacks/jwt.md)
    * [XPath Injection](web-app-penetration-testing/attacks/xpath.md)
    * [LDAP Injection](web-app-penetration-testing/attacks/ldap.md)
    * [SQL Injection](web-app-penetration-testing/attacks/sql-injection.md)
    * [No SQL Injection](web-app-penetration-testing/attacks/no-sql-injection.md)
    * [DNS Rebinding](web-app-penetration-testing/attacks/dns-rebinding.md)
    * [Cross Site Scripting (XSS)](web-app-penetration-testing/attacks/xss.md)
    * [PDF Generation Vulnerablilities](web-app-penetration-testing/attacks/pdf-injection.md)
    * [Cross Origin Resource Sharing (CORS)](web-app-penetration-testing/attacks/cors.md)
    * [Command Injection](web-app-penetration-testing/attacks/command-injection.md)
    * [File Inclusion](web-app-penetration-testing/attacks/file-inclusion.md)
    * [File Upload Attacks](web-app-penetration-testing/attacks/file-upload.md)
    * [Parameter Pollution](web-app-penetration-testing/attacks/param-pollution.md)
    * [XML External Entity Injection (XXE)](web-app-penetration-testing/attacks/xxe.md)
  * [⚒️ Remediations](web-app-penetration-testing/attacks/remediations.md)


<!--
* [🤖 Android Penetration Testing](android-pentesting/README.md)
  * [Basics](android-pentesting/basics.md)
  * [Setup](android-pentesting/setup.md)
  * [Static Analysis](android-pentesting/static-analysis.md)
  * [Dynamic Analysis](android-pentesting/dynamic-analysis/README.md)
    * [Enumerating Local Storage](android-pentesting/dynamic-analysis/local_storage.md)
    * [Insecure Logging](android-pentesting/dynamic-analysis/insecure-logging.md)
    * [Root Detection Bypass](android-pentesting/dynamic-analysis/root-bypass.md)
    * [SSL Pinning Bypass](android-pentesting/dynamic-analysis/ssl-pinning-bypass.md)
    * [Biometric Bypass](android-pentesting/dynamic-analysis/biometric-bypass.md)
    * [Authentication Bypass](android-pentesting/dynamic-analysis/auth-bypass.mdd)
    * [Intent Exploitation](android-pentesting/dynamic-analysis/intent.md)
    * [WebViews Exploiatation](android-pentesting/dynamic-analysis/webviews.md)
    * [Deep Links Exploitation](android-pentesting/dynamic-analysis/deeplinks.md)
    * [Hooking Methods](android-pentesting/dynamic-analysis/hooking-methods.md)
  * [⚒️ Remediations](android-pentesting/remediations.md)
-->

* [🕷️ Malware Development](malware-dev/README.md)
  * [Windows Defender Bypass](malware-dev/defender-bypass.md)


* [☁️ Cloud Pentesting](cloud-pentesting/README.md)
  * [GCP](cloud-pentesting/gcp.md)
  * [AWS](cloud-pentesting/aws.md)
  <!--* [Azure](cloud-pentesting/azure.md) -->

<!--
* [🧰 Methodology](methodology/README.md)
  * [External Pentest](methodology/external_pentest.md)
  * [Internal Pentest](methodology/internal_pentest.md) 
  * [Reporting](methodology/reporting.md) 
-->

* [🛠️ Miscellaneous](miscellaneous/README.md)
  * [Pivoting & Tunneling](miscellaneous/pivoting-and-tunneling.md)
  * [File Transfer Methods](miscellaneous/file-transfer-methods.md)
  * [Password Cracking](miscellaneous/password-cracking.md)
  * [Shells & Payloads](miscellaneous/shells-and-payloads.md)
  * [Tmux](miscellaneous/tmux.md)
  * [Burp Certs in Android](miscellaneous/android_burp.md)

* [🛠️ CRTO Cheatsheet](crto/README.md)
  * [Initial Access](crto/ia.md)
  * [Persistence](crto/persis.md)
  * [Post Ex & PrivEsc](crto/postex.md)
  * [Discovery](crto/disc.md)
  * [Lateral Movement](crto/lm.md)
  * [Pivoting](crto/piv.md)
  * [Kerberos](crto/kerb.md)
  * [MSSQL](crto/sql.md)
  * [Domain Persistence](crto/dp.md)
  * [Cross Forest Attacks](crto/cf.md)
  * [Defense Evasion](crto/evasion.md)
