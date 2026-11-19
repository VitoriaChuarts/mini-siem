# Formato de alerta

Todos os sensores enviam alertas neste formato JSON para `POST /api/alerts`:

```json
{
  "source": "honeypot | nids | phishing",
  "timestamp": "2026-11-18T14:30:00Z",
  "srcIp": "203.0.113.5",
  "eventType": "ssh_login_attempt",
  "severity": "low | medium | high",
  "details": {}
}
```
