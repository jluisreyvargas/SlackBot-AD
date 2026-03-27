# 🤖 SlackBot Active Directory — Windows Server 2025

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.0%2B-black?logo=flask)](https://flask.palletsprojects.com/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20Server%202025-blue?logo=windows)](https://www.microsoft.com/en-us/windows-server)
[![Cloudflare](https://img.shields.io/badge/Tunnel-Cloudflared-orange?logo=cloudflare)](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Bot de Slack para consultar usuarios de **Active Directory** a través de un tunel **Cloudflare** (cloudflared), desplegado en un **Domain Controller Windows Server 2025**.

---

## Arquitectura

```
Slack (slash command)
        |
        v
Cloudflare Tunnel (cloudflared)
        |  subdomain.tudominio.com -> localhost:3000
        v
Flask App (Python 3.10+) — Windows Server 2025 DC
        |
        v
PowerShell + Modulo ActiveDirectory
        |
        v
Active Directory (LDAP local)
```

El bot recibe comandos slash de Slack, verifica la firma HMAC-SHA256, ejecuta scripts PowerShell locales contra el AD y responde de forma asincrona usando el response_url de Slack para evitar el timeout de 3 segundos.

---

## Requisitos

### Servidor (Domain Controller)
- Windows Server 2025
- PowerShell 5.1+
- Modulo ActiveDirectory instalado (RSAT o rol AD DS)
- Python 3.10+
- cloudflared instalado y configurado como servicio Windows

### Slack App
- Slash Command con URL: https://subdomain.tudominio.com/slack/events
- Permisos OAuth: commands, chat:write
- Signing Secret y Bot Token disponibles

---

## Instalacion

### 1. Clonar el repositorio

```powershell
git clone https://github.com/tuusuario/slackbot-ad.git
cd slackbot-ad
```

### 2. Crear entorno virtual e instalar dependencias

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### 3. Crear fichero .env

```powershell
copy .env.example .env
notepad .env
```

---

## Configuracion

### Variables de entorno (.env)

```
SLACK_SIGNING_SECRET=tu_signing_secret
SLACK_BOT_TOKEN=xoxb-tu-bot-token
```

### Ajuste del dominio en app.py

Localiza esta linea en get_ou_mapping() y ajusta al DN de tu dominio:

```python
mapping["users"] = "CN=Users,DC=tudominio,DC=local"
```

Puedes obtener el valor correcto con:

```powershell
Get-ADDomain | Select-Object DistinguishedName
```

### Cloudflared (config.yml)

```yaml
tunnel: <tunnel-id>
credentials-file: C:\cloudflared\<tunnel-id>.json
ingress:
  - hostname: subdomain.tudominio.com
    service: http://localhost:3000
  - service: http_status:404
```

---

## Comandos disponibles

| Comando | Descripcion |
|---|---|
| `/checkpass` | Muestra ayuda y OUs disponibles |
| `/checkpass usuario@dominio.local` | Caducidad de contrasena de un usuario |
| `/checkpass ou <nombre>` | Usuarios habilitados de una OU por nombre legible |
| `/checkpass all` | Todos los usuarios habilitados del AD |

### Ejemplos

```
/checkpass jose.rey@empresa.local
/checkpass ou remote laptops users
/checkpass ou cuentas de servicio
/checkpass all
```

### Codigos de color

| Emoji | Significado |
|---|---|
| Verde | Contrasena valida o nunca caduca |
| Naranja | Caduca en 7 dias o menos |
| Rojo | Contrasena ya caducada |

### Ejemplo de respuesta

```
TODOS usuarios habilitados
        Usuario        Expira      Dias  Ult.Cambio  Nunca?
------  -------------  ----------  ----  ----------  ------
Verde   Administrador  NEVER       -     2024-10-12  True
Verde   jose           NEVER       -     2026-01-07  True
Verde   svc_slackbot   NEVER       -     2026-03-22  True
Verde   juan           2026-05-07  40    2026-03-26  False
```

---

## Estructura del proyecto

```
slackbot-ad/
|-- app.py
|-- requirements.txt
|-- .env.example
|-- .gitignore
|-- README.md
```

---

## Despliegue como servicio Windows (NSSM)

Descarga NSSM desde https://nssm.cc/download y copia nssm.exe en C:\Windows\System32.

```powershell
nssm install SlackBotAD "C:\bots\venv\Scripts\python.exe" "C:\bots\app.py"
nssm set SlackBotAD AppDirectory  "C:\bots"
nssm set SlackBotAD DisplayName   "Slack Bot Active Directory"
nssm set SlackBotAD Description   "Bot Slack para consultas AD via Cloudflare Tunnel"
nssm set SlackBotAD Start         SERVICE_AUTO_START
nssm set SlackBotAD AppStdout     "C:\bots\logs\slackbot.log"
nssm set SlackBotAD AppStderr     "C:\bots\logs\slackbot_error.log"
nssm start SlackBotAD
```

Gestion del servicio:

```powershell
nssm status  SlackBotAD
nssm restart SlackBotAD
nssm stop    SlackBotAD
nssm remove  SlackBotAD
```

---

## Debug y Troubleshooting

### Ver OUs detectadas

Visita desde el servidor:

```
http://localhost:3000/debug
```

Devuelve JSON con todas las OUs y sus DNs. Desactiva en produccion.

### Problemas comunes

| Error | Causa | Solucion |
|---|---|---|
| OU xxx no encontrada | Nombre no coincide | Consultar /debug |
| Invalid signature | Signing secret incorrecto | Revisar .env |
| Import-Module ActiveDirectory falla | RSAT no instalado | Add-WindowsFeature RSAT-AD-PowerShell |
| Timeout PowerShell | AD con muchos usuarios | Aumentar timeout= en la funcion |
| PasswordNeverExpires siempre True | Fine-grained password policy | Revisar PSO aplicadas |

---

## Seguridad

- Verificacion HMAC-SHA256 de cada peticion Slack
- Ventana de 5 minutos en timestamp para prevenir replay attacks
- Respuestas ephemeral — solo el usuario que ejecuta el comando ve los resultados
- Credenciales en .env — nunca hardcodeadas en el codigo
- .env excluido del repositorio via .gitignore
- Se recomienda cuenta de servicio dedicada svc_slackbot con permisos de solo lectura en AD

### Crear cuenta de servicio con permisos minimos

```powershell
New-ADUser -Name "svc_slackbot" -SamAccountName "svc_slackbot" `
           -UserPrincipalName "svc_slackbot@tudominio.local" `
           -AccountPassword (Read-Host -AsSecureString) `
           -PasswordNeverExpires $true -Enabled $true
```

---

## Licencia

MIT License

> Desarrollado para Windows Server 2025 con Active Directory y Cloudflare Tunnel.
> Tested on: Windows Server 2025 · Python 3.12 · Flask 3.0 · PowerShell 5.1
"# SlackBot-AD" 
