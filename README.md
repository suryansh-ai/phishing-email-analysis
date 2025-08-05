# 🛡️ Phishing Email Analysis Report

## 📌 Task Objective
To analyze a suspicious email and identify phishing indicators such as email spoofing, mismatched URLs, urgent language, and header anomalies.

---

## 📧 Sample Phishing Email Summary

**Subject:** Urgent Action Required – Your Amazon Account is Suspended!  
**Sender Email:** support@secure-amaz0n.com  
**Date Received:** 05-07-2025  
**Attachment/Link:** https://amaz0n-verification.com/login

---

## 🕵️‍♂️ Phishing Indicators Found

| Indicator Type         | Details                                                                 |
|------------------------|-------------------------------------------------------------------------|
| 📬 **Spoofed Email**    | Email mimics Amazon but has a suspicious domain                        |
| 🔗 **Mismatched Link**  | Text shows legitimate domain but points to phishing site               |
| 🧾 **Malicious Intent** | Link attempts to steal login credentials                                |
| 📢 **Urgent Language**  | "Your account will be permanently disabled!"                           |
| ✍️ **Spelling Errors**  | Minor grammar and format inconsistencies                               |
| 🧠 **Social Engineering** | Tries to scare user into clicking the link immediately                 |

---

## 🛠️ Tools Used

| Tool                  | Purpose                            | Link                                             |
|-----------------------|------------------------------------|--------------------------------------------------|
| MXToolbox             | Email Header Analysis              | https://mxtoolbox.com/EmailHeaders.aspx          |
| VirusTotal            | URL/Attachment Scan                | https://www.virustotal.com/                      |

---

## 🧪 Email Header Analysis

**Tool Used:** MXToolbox  
**Findings:**
- SPF Check: ❌ Failed  
- DKIM: ❌ Not present  
- Return Path: Doesn't match sender domain  
- Source IP: Located in suspicious country

---

## Files Included
- `sample_email.txt`
- Screenshots

---

## ✅ Conclusion

The analyzed email contains multiple indicators of phishing. It is likely crafted to trick the recipient into revealing credentials or installing malware.

---

## 📂 Repository Structure

```
phishing-email-analysis/
│
├── README.md
├── sample_email.txt
├── screenshots/
│   ├── MXToolbox Email Header Analyzer.png
│   └── Virustotal-sann.png
│   └── Virustotal-sannn.png
```

---

## ✍️ Created By

**Name:** Suryansh Pandey

**Internship:** Cyber Security Internship – Task 2  

**Date:** [05/08/2025]
