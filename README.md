# DNS over HTTPS (DoH) for Secure Public Key Authentication

### Overview
This project explores using **DNS over HTTPS (DoH)** to improve internet security by handling **public key authentication**, reducing reliance on traditional **Certification Authorities (CAs)**.

### Why This Matters
- **CAs can be a weak point** — if compromised, they can break the trust model.
- **Current revocation methods** (CRLs, OCSP) are slow, inefficient, or privacy-invasive.
- **DoH** is already supported in modern browsers and provides a more private, efficient solution.

### Key Features
- ✅ **CA-Free Authentication** — Trust is shifted to secure DoH servers.
- 🔁 **Custom Key Lifetimes** — Key owners can set expiration periods, reducing revocation needs.
- 🛡️ **Privacy-Friendly** — No OCSP queries, which can reveal browsing behavior.
- 🌐 **Built on Existing DoH Infrastructure** — Simple integration using encrypted DNS.

## Proof of Concept
This project includes a working demo showing how:
- DoH servers can perform both **DNS resolution** and **public key verification**.
- We can reduce reliance on traditional CA behavior.
- Short-lived keys can replace conventional revocation methods.

---

