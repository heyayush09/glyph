# glyph-proxy

**glyph-proxy** is a high-performance, identity-aware reverse proxy built in Go.  
It enables secure Single Sign-On (SSO) using **OIDC** and enforces fine-grained access control policies for internal web applications.  
Designed for local development and production use in cloud-native environments.

---

## ✨ Features

- 🔐 **OIDC-based SSO** with secure session cookies
- 🔁 **Reverse proxy** with static IP or dynamic targets
- 📜 Declarative `config.yaml` powered by Viper
- 🔧 Developer-first **CLI** using Cobra
- 🌐 **TLS** with automatic mkcert support in dev
- ⚖️ Fine-grained **access policies** (users/groups)
- 🛡️ Hardened with secure cookies, JWTs (RS256), and CSRF protection
- 📈 **Observability**: `/metrics` endpoint and audit logging
- 🧠 Identity-aware headers (`X-User-*`) injected into proxied requests

---

## 📦 Tech Stack

| Component        | Technology                     |
|------------------|-------------------------------|
| Language         | Go                             |
| CLI              | [Cobra](https://github.com/spf13/cobra)         |
| Config Mgmt      | [Viper](https://github.com/spf13/viper)         |
| HTTP Routing     | [Chi](https://github.com/go-chi/chi)            |
| OIDC             | [go-oidc](https://github.com/coreos/go-oidc)    |
| JWT              | [golang-jwt](https://github.com/golang-jwt/jwt) |
| AWS Integration  | [aws-sdk-go-v2](https://github.com/aws/aws-sdk-go-v2) |
| Hot Reload       | [Air](https://github.com/cosmtrek/air)          |

---

# 🚀 Getting Started

## 1. Clone & Install

```bash
git clone https://github.com/heyayush09/glyph-proxy.git
cd glyph-proxy

# Setup Go modules and dependencies
go mod tidy
```

## 2. Run with Hot Reload (Air)

```bash
go install github.com/air-verse/air@latest
air
```

## 3. Example `config.yaml`

```yaml
listen: ":443"

tls:
  mode: "auto"  # or "manual"
  cert_file: ""
  key_file: ""

oidc:
  issuer: "https://accounts.google.com"
  client_id: "your-client-id"
  client_secret_env: "GOOGLE_CLIENT_SECRET"

routes:
  - from: app.localhost
    to: http://localhost:3000
    allowed_users:
      - ayush@example.com
  - from: grafana.glyph.company.internal
    target:
      type: ip
      ip: "192.168.1.10"
    allowed_groups:
      - infra-admins
```

---

## 🔐 Security Principles

- Enforced **TLS 1.2+**
- Secure cookies: `HttpOnly`, `SameSite=Strict`, `Secure`
- RS256 JWT signing (**no shared secrets**)
- OIDC flow hardened with **state + nonce**
- **Refresh token rotation**
- Hardened headers: `HSTS`, `X-Frame-Options`, `Content-Security-Policy`, etc.
- Structured **audit logging** and **Prometheus metrics**

---

## 📈 Observability

- `/metrics` – Prometheus-compatible endpoint
- Structured logs for:
  - Login/logout
  - Policy checks
  - Audit trails

---

## 👷 Contributing

This project is under active development. Feedback, PRs, and ideas welcome!

---

## 📄 License

MIT © Ayush Mani

---