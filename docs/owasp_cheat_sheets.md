# OWASP Top 10 & Perimeter Transport Security Guide

## 1. Perimeter Header & Transport Protections

### Secure Nginx / Kubernetes Ingress Configuration
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: oneshield-edge-ingress
  annotations:
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
    nginx.ingress.kubernetes.io/configuration-snippet: |
      more_set_headers "X-Frame-Options: DENY";
      more_set_headers "X-Content-Type-Options: nosniff";
      more_set_headers "X-XSS-Protection: 1; mode=block";
      more_set_headers "Strict-Transport-Security: max-age=31536000; includeSubDomains";
spec:
  rules:
  - host: api.bank.com
```

## 2. OWASP Top 10 Mapping Reference
- **A01:2021-Broken Access Control**: Enforce RBAC/ABAC at backend service interfaces (`@PreAuthorize`).
- **A03:2021-Injection**: Use parameterized queries for SQL, HQL, and PL/SQL (`:parameter`).
- **A05:2021-Security Misconfiguration**: Enforce TLS 1.3, SSL redirection, and security headers at Kubernetes Ingress.
