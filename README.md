# Securing Internet Connections with DNS over HTTPS (DoH) for Public Key Authentication

# Overview
Transport Layer Security (TLS) and X.509 certificates are fundamental to internet security, enabling secure connections between users and websites. These certificates are issued by Certification Authorities (CAs), but the current CA-based authentication model has several limitations. Trust is placed on the CA’s integrity, and any compromise in their behavior or system can jeopardize security.

Traditional methods for certificate revocation, such as the Online Certificate Status Protocol (OCSP) and Certificate Revocation Lists (CRL), come with significant challenges:
  - CRL Updates: Inefficient and slow to propagate.
  - OCSP: Raises privacy concerns and introduces delays in secure connections.
This project seeks to shift the trust model from CAs to a more secure and efficient system using DNS over HTTPS (DoH) servers. DoH servers, already deployed in most web browsers, can simultaneously handle domain name resolution and public key authentication, reducing dependency on CAs. Additionally, this approach allows public key owners to set custom key lifetimes, minimizing the need for conventional revocation methods.

# Key Features
  - CA-Independent Authentication: Relocates the trust model from potentially unreliable CAs to trusted DoH servers.
  - Efficient Revocation: Public key owners can define key lifetimes, reducing the need for frequent revocation mechanisms.
  - Privacy-Friendly: Addresses OCSP’s privacy concerns by eliminating the need for OCSP queries.
  - DNS over HTTPS Integration: Leverages existing DoH infrastructure for secure, encrypted DNS queries and key
    authentication.
# Proof of Concept
The project includes a fully functional proof of concept to demonstrate:
  - How DoH servers can securely manage both DNS resolution and public key authentication.
  - The reduction in reliance on CA behavior and integrity.
  - The feasibility of custom key lifetimes in minimizing revocation needs.
