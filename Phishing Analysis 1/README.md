# First Phishing Email Analysis Documentation

## 1. Objective

In this lab, I conducted a deep-dive analysis of a suspicious email to the recipient. My goal was to:

1. Trace the email’s path through mail servers.  
2. Inspect key header fields for inconsistencies.  
3. Validate sender reputation using OSINT.  
4. Determine whether the email is a phishing attempt.

---

## 2. Email Header Analysis

### 2.1 Mail Server Path (`Received` fields)

This email passed through **seven** `Received` hops. The **first** (topmost) entry indicates the final hop before delivery; the **seventh** (bottom) entry shows the initial server:

![Received Fields Screenshot](images/recieved.png)

> **Closest to sender:** `mail.yobow.cn`

![Received Fields Screenshot](images/recievedclosest.png)


---

### 2.2 Authentication Results

- **SPF:** `softfail`  
  The sender IP (`183.56.179.169`) is **not** authorized in the domain’s SPF record, so it was marked as spam but still delivered.  
- **DKIM:** `none`  
- **DMARC:** `none`  

![Authentication-Results Screenshot](images/auth.png)

---

### 2.3 Envelope & Display Fields

- **Return-Path:** `p.chambers@sasktel.net`  
- **From:** `Mrs Janet Yellen <p.chambers@sasktel.net>`  
- **Reply-To:** `agentcynthiajamescontact01@gmail.com`  
- **To:** `Undisclosed recipients`  


![Return-Path Screenshot](images/returnpath.png)
![From Screenshot](images/from.png)
![Reply-To Screenshot](images/replyto.png)
![To Screenshot](images/to.png)

The mismatch between **From** and **Reply-To**, plus undisclosed recipients, are classic phishing indicators.

---

### 2.4 Message Metadata

- **Subject:** `Attention Dear Beneficiary`  
- **Date:** `Wed, 6 Dec 2023 05:00:12 -0800`  
- **Message-ID:** `20231206125957.6414E20EB5FD@mail.yobow.cn`  
- **X-Mailer:** `Microsoft Outlook Express`  
- **Content-Type:** `text/html` (1 occurrence)

![Subject Screenshot](images/subject.png)
![Date Screenshot](images/date.png)
![Message-ID Screenshot](images/msgid.png)
![X-Mailer Screenshot](images/xmailer.png)
![Content-Type Screenshot](images/contenttype1.png)


---

## 3. Email Body

![Email-Body Screenshot](images/body.png)

The HTML-formatted body promises an inheritance of **16 million USD** and urges the recipient to reply to two “diplomatic agents”:


- **Cynthia R. James**  
  `agentcynthiajamescontact01@gmail.com`
  

- **John Williams**  
  `dr.philipmaxwell303@gmail.com`
  
![Email-Body Screenshot](images/body2.png)

Clearly, the offer is too good to be true and designed to lure victims into a reply.

---

## 4. OSINT & Reputation Checks

### 4.1 Sender Mail Server (`yobow.cn`)

- **Domain Creation:** July 18, 2014  
- **Location:** Beijing, China  
- **VirusTotal:** Multiple reports of similar spam/phishing campaigns.

![Domain-OSINT Screenshot](images/whois(yobow.cn).jpg)
![Domain-OSINT Screenshot](images/virustotal(yobow.cn).jpg)

---

### 4.2 Sender Domain (`sasktel.net`)

- **Domain Creation:** April 5, 2000  
- **Location:** Toronto, Canada  
- **WHOIS/DomainTools:** Legitimate ISP  
- **VirusTotal:** No vendor flags for phishing.

![Domain-OSINT Screenshot](images/whois(sasktel.net).png)
![Domain-OSINT Screenshot](images/virustotal(sasktel.net).png)

### 4.3 Sender IP (`183.56.179.169`)

- **AbuseIPDB:** Repeated spam reports  
- **IPVoid:** Flagged by 3 blacklists  
- **VPN Check:** Not associated with any VPN service (according ipinfo.io)

![IP-Reputation Screenshot](images/ipreputation.png)
![IP-Reputation Screenshot](images/vpn.png)

---

## 5. Conclusions & Recommendations

1. **Phishing Indicators**  
   - SPF softfail  
   - Mismatched From/Reply-To  
   - Spam-reported IP  
   - Unrealistic financial promise  

2. **Action Items**  
   - **Delete** the email and block the sender.  
   - **Search** SIEM/email gateway logs for subject `"Attention Dear Beneficiary"` and any traffic to/from:
     - `p.chambers@sasktel.net`  
     - `agentcynthiajamescontact01@gmail.com`  
     - `dr.philipmaxwell303@gmail.com`  
     - Domain `sasktel.net`

3. **Next Steps**  
   - Notify users and the security team of this phishing campaign.  
   - Update email filtering rules to flag future messages from `yobow.cn`.
  
### 6. Skills Learned

- Email header forensics: parsing and interpreting Received, Authentication-Results, Message-ID, and X‑headers

- Authentication analysis: understanding SPF, DKIM, and DMARC outcomes and implications

- Mail flow tracing: mapping an email’s journey through multiple servers

- OSINT investigations: performing WHOIS, VirusTotal, AbuseIPDB, and IPVoid lookups on domains and IP addresses

- Social‑engineering detection: recognizing mismatched From/Reply-To, undisclosed recipients, and lure-based subject lines


---
