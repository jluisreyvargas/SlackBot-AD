# 🤖 SlackBot Active Directory — Windows Server 2025

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.0%2B-black?logo=flask)](https://flask.palletsprojects.com/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20Server%202025-blue?logo=windows)](https://www.microsoft.com/en-us/windows-server)
[![Cloudflare](https://img.shields.io/badge/Tunnel-Cloudflared-orange?logo=cloudflare)](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Bot de Slack para gestionar usuarios y equipos de **Active Directory** a través de un túnel **Cloudflare**, desplegado como servicio en un **Domain Controller Windows Server 2025**.

---

## 📋 Tabla de Contenidos

- [Arquitectura](#arquitectura)
- [Requisitos](#requisitos)
- [Instalación de la aplicación](#instalación-de-la-aplicación)
- [Despliegue como servicio Windows con NSSM](#despliegue-como-servicio-windows-con-nssm)
- [Configuración de Cloudflare Tunnel](#configuración-de-cloudflare-tunnel)
- [Configuración de Slack App](#configuración-de-slack-app)
- [Delegación de permisos en AD](#delegación-de-permisos-en-ad)
- [Comandos disponibles](#comandos-disponibles)
- [Estructura del proyecto](#estructura-del-proyecto)
- [Debug y Troubleshooting](#debug-y-troubleshooting)
- [Seguridad](#seguridad)

---

## 🏗️ Arquitectura

```
Slack (slash command /checkpass)
        │
        ▼
Cloudflare Network
        │  slackbot.dominio.es  →  CNAME → <Tunnel-ID>.cfargotunnel.com
        ▼
Cloudflare Tunnel Connector (cloudflared) — Windows Server 2025 DC
        │  túnel → http://localhost:3000
        ▼
Flask App (Python 3.10+) — puerto 3000
        │
        ▼
PowerShell + Módulo ActiveDirectory
        │
        ▼
Active Directory (LDAP local)
```

El bot recibe comandos slash de Slack, verifica la firma HMAC-SHA256, ejecuta scripts
PowerShell locales contra el AD y responde de forma **asíncrona** usando el `response_url`
de Slack para evitar el timeout de 3 segundos.

---

## ✅ Requisitos

### Servidor (Domain Controller)
- Windows Server 2025
- PowerShell 5.1+
- Módulo `ActiveDirectory` instalado (rol AD DS o RSAT)
- Python 3.10+
- `cloudflared` instalado como servicio Windows

### DNS / Cloudflare
- Dominio gestionado en Cloudflare
- Cuenta en Cloudflare Zero Trust (gratuita)

### Slack
- Slack App creada en [api.slack.com](https://api.slack.com)
- Slash Command configurado apuntando a `https://slackbot.dominio.es/slack/events`
- Permisos OAuth: `commands`, `chat:write`

---

## 📦 Instalación de la aplicación

### 1. Clonar o copiar los ficheros

Coloca todos los ficheros del repositorio en una carpeta del servidor:

```
C:\bots\
  ├── app.py
  ├── requirements.txt
  └── .env
```

### 2. Instalar dependencias Python

Ejecuta una sola vez desde esa carpeta:

```powershell
cd C:\bots
pip install -r requirements.txt
```

### 3. Crear el fichero .env

```powershell
copy .env.example .env
notepad .env
```

Contenido del `.env`:

```env
SLACK_SIGNING_SECRET=tu_signing_secret_de_slack
SLACK_BOT_TOKEN=xoxb-tu-bot-token
```

### 4. Ajustar el dominio en app.py

Localiza estas líneas en `get_ou_mapping()` y sustitúyelas con el DN de tu dominio:

```python
mapping["users"]     = "CN=Users,DC=tudominio,DC=local"
mapping["computers"] = "CN=Computers,DC=tudominio,DC=local"
```

> 💡 `CN=Users` y `CN=Computers` son contenedores builtin del AD (no son OUs reales),
> por eso se añaden manualmente. El resto de OUs se detectan automáticamente.

Para obtener el DN correcto de tu dominio:

```powershell
Get-ADDomain | Select-Object DistinguishedName
```

---

## 🪟 Despliegue como servicio Windows con NSSM

El bot se gestiona como servicio Windows mediante **NSSM** (Non-Sucking Service Manager),
que arranca `python app.py` automáticamente con el servidor.

### 1. Descargar NSSM

Descarga desde [https://nssm.cc/download](https://nssm.cc/download) y copia `nssm.exe` en:

```
C:\Windows\System32\nssm.exe
```

### 2. Instalar el servicio

```powershell
nssm install SlackBotAD "C:\Python312\python.exe" "C:\bots\app.py"
nssm set SlackBotAD AppDirectory   "C:\bots"
nssm set SlackBotAD DisplayName    "Slack Bot Active Directory"
nssm set SlackBotAD Description    "Bot Slack para gestión AD via Cloudflare Tunnel"
nssm set SlackBotAD Start          SERVICE_AUTO_START
nssm set SlackBotAD AppStdout      "C:\bots\logs\slackbot.log"
nssm set SlackBotAD AppStderr      "C:\bots\logs\slackbot_error.log"
```

> 💡 Crea la carpeta de logs antes: `mkdir C:\bots\logs`

### 3. Arrancar el servicio

```powershell
nssm start SlackBotAD
```

### 4. Gestión del servicio

```powershell
nssm status  SlackBotAD   # Ver estado
nssm restart SlackBotAD   # Reiniciar tras cambios en app.py
nssm stop    SlackBotAD   # Parar
nssm remove  SlackBotAD   # Desinstalar servicio
```

---

## ☁️ Configuración de Cloudflare Tunnel

El túnel expone el servicio Flask local (`http://localhost:3000`) de forma segura en internet
sin abrir puertos en el firewall.

### Paso 1 — Crear el Tunnel en Cloudflare Zero Trust

1. Accede a [Cloudflare Zero Trust](https://one.dash.cloudflare.com)
2. Ve a **Networks → Tunnels → Create a tunnel**
3. Selecciona **Cloudflared** como tipo de conector
4. Asigna un nombre al túnel, por ejemplo: `SlackBot`
5. Cloudflare genera un **Tunnel ID** (UUID) y un **token de instalación**

### Paso 2 — Instalar el connector en el servidor

Cloudflare te proporciona un comando listo para ejecutar en el servidor.
Ejecútalo en PowerShell como Administrador en el DC:

```powershell
# Comando generado por Cloudflare (ejemplo):
cloudflared.exe service install eyJhIjoiABC...TOKEN_COMPLETO...XYZ
```

Esto instala y registra `cloudflared` como **servicio Windows** asociado a tu túnel.
Verifica que el servicio esté corriendo:

```powershell
Get-Service cloudflared
```

### Paso 3 — Publicar el hostname público

En Cloudflare Zero Trust, dentro del túnel creado:

1. Ve a la pestaña **Public Hostnames**
2. Haz clic en **Add a public hostname**
3. Rellena los campos:

| Campo | Valor |
|---|---|
| **Subdomain** | `slackbot` |
| **Domain** | `dominio.es` |
| **Service Type** | `HTTP` |
| **Service URL** | `http://localhost:3000` |

4. Guarda — Cloudflare publicará `https://slackbot.dominio.es`

> 💡 Puedes añadir más Public Hostnames al mismo túnel para exponer otros servicios
> del mismo servidor (Grafana, otro bot, etc.) sin instalar nada adicional.

### Paso 4 — Registro DNS (CNAME)

Cloudflare crea automáticamente el registro DNS al configurar el Public Hostname.
En la zona DNS del dominio verás:

| Type | Name | Content | Proxy |
|---|---|---|---|
| `CNAME` | `slackbot` | `<Tunnel-ID>.cfargotunnel.com` | ✅ Proxied |

En la interfaz de Cloudflare, el contenido puede mostrarse como el alias del túnel
(el nombre que le diste, ej: `SlackBot`) que internamente apunta al UUID del túnel.

> ⚠️ Asegúrate de que el registro tenga **Proxy activado** (nube naranja).

---

## 💬 Configuración de Slack App

1. Ve a [https://api.slack.com/apps](https://api.slack.com/apps) → **Create New App**
2. Selecciona **From scratch**, asigna nombre y workspace
3. Ve a **Slash Commands → Create New Command**:

| Campo | Valor |
|---|---|
| **Command** | `/checkpass` |
| **Request URL** | `https://slackbot.dominio.es/slack/events` |
| **Short Description** | `Gestiona usuarios y equipos en Active Directory` |

4. Ve a **OAuth & Permissions** → copia el **Bot Token** (`xoxb-...`)
5. Ve a **Basic Information** → copia el **Signing Secret**
6. Instala la app en el workspace

---

## 🔐 Delegación de permisos en AD

La cuenta `svc_slackbot` necesita permisos delegados en las OUs para ejecutar acciones de escritura.
Los permisos de **solo lectura** (listar usuarios, equipos, caducidades) no requieren delegación adicional.

### Permisos necesarios por funcionalidad

| Funcionalidad | Permiso AD | Delegación necesaria |
|---|---|---|
| Ver usuarios / equipos / caducidades | Lectura (por defecto) | ❌ No |
| Reset contraseña | `ExtendedRight: Reset Password` + `Write pwdLastSet` | ✅ Sí |
| Habilitar / Deshabilitar cuenta | `Write userAccountControl` | ✅ Sí |
| Desbloquear cuenta (futuro) | `Write lockoutTime` | ✅ Sí |

### Script de delegación completo

Ejecutar como **Domain Admin** en el DC:

```powershell
Import-Module ActiveDirectory

$serviceAccount = "svc_slackbot"
$targetOUs = @(
    "OU=Remote Laptops Users,DC=tudominio,DC=local",
    "OU=Users,DC=tudominio,DC=local"
    # Añade más OUs si es necesario
)

$schemaPath = (Get-ADRootDSE).schemaNamingContext
$configPath = (Get-ADRootDSE).configurationNamingContext

$guidmap = @{}
Get-ADObject -SearchBase $schemaPath -LDAPFilter "(schemaidguid=*)" `
    -Properties lDAPDisplayName, schemaIDGUID |
    ForEach-Object { $guidmap[$_.lDAPDisplayName] = [System.GUID]$_.schemaIDGUID }

$extmap = @{}
Get-ADObject -SearchBase "CN=Extended-Rights,$configPath" `
    -LDAPFilter "(objectclass=controlAccessRight)" `
    -Properties displayName, rightsGUID |
    ForEach-Object { $extmap[$_.displayName] = [System.GUID]$_.rightsGUID }

$sid = New-Object System.Security.Principal.SecurityIdentifier (
    (Get-ADUser $serviceAccount).SID
)

foreach ($ouDN in $targetOUs) {
    Write-Host "Aplicando delegacion en: $ouDN" -ForegroundColor Yellow
    $acl = Get-Acl "AD:\$ouDN"

    # Reset Password
    $acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
        $sid, "ExtendedRight", "Allow", $extmap["Reset Password"], "Descendents", $guidmap["user"]))

    # Change Password
    $acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
        $sid, "ExtendedRight", "Allow", $extmap["Change Password"], "Descendents", $guidmap["user"]))

    # Write pwdLastSet (forzar cambio en proximo login)
    $acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
        $sid, "WriteProperty", "Allow", $guidmap["pwdLastSet"], "Descendents", $guidmap["user"]))

    # Write userAccountControl (habilitar/deshabilitar cuenta)
    $acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
        $sid, "WriteProperty", "Allow", $guidmap["userAccountControl"], "Descendents", $guidmap["user"]))

    # Write lockoutTime (desbloquear cuenta)
    $acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
        $sid, "WriteProperty", "Allow", $guidmap["lockoutTime"], "Descendents", $guidmap["user"]))

    Set-Acl "AD:\$ouDN" $acl
    Write-Host "  OK" -ForegroundColor Green
}
```

---

## 💬 Comandos disponibles

| Comando | Descripción | Confirmación |
|---|---|---|
| `/checkpass` | Muestra ayuda, leyenda y OUs disponibles | — |
| `/checkpass usuario@dominio` | Caducidad de contraseña de un usuario | ❌ |
| `/checkpass ou <nombre>` | Usuarios de una OU (habilitados y deshabilitados) | ❌ |
| `/checkpass all` | Todos los usuarios del AD | ❌ |
| `/checkpass computers <nombre>` | Equipos de una OU (habilitados y deshabilitados) | ❌ |
| `/checkpass reset usuario@dominio` | Solicitar reset de contraseña | ✅ `resetconfirm` |
| `/checkpass resetconfirm usuario@dominio` | Confirmar reset de contraseña | — |
| `/checkpass enable usuario@dominio` | Habilitar cuenta de usuario | ❌ |
| `/checkpass disable usuario@dominio` | Solicitar deshabilitar cuenta | ✅ `disableconfirm` |
| `/checkpass disableconfirm usuario@dominio` | Confirmar deshabilitar cuenta | — |

### Ejemplos de uso

```
/checkpass jose.rey@empresa.local
/checkpass ou remote laptops users
/checkpass ou cuentas de servicio
/checkpass all
/checkpass computers remote laptops users
/checkpass computers computers
/checkpass reset juan@empresa.local
/checkpass resetconfirm juan@empresa.local
/checkpass enable pedro@empresa.local
/checkpass disable maria@empresa.local
/checkpass disableconfirm maria@empresa.local
```

### Leyenda de emojis

| Emoji | Significado |
|---|---|
| 🟢 | Cuenta activa, contraseña válida |
| 🟠 | Contraseña caduca en 7 días o menos |
| 🔴 | Contraseña ya caducada |
| ⛔ | Cuenta deshabilitada |

### Ejemplo de respuesta en Slack

```
TODOS los usuarios
        Usuario        Expira      Dias  Ult.Cambio  Nunca?  Activo?
------  -------------  ----------  ----  ----------  ------  -------
🟢      jose           NEVER       -     2026-01-07  True    True
🟢      juan           2026-05-07  40    2026-03-26  False   True
🟠      ana            2026-04-02  6     2026-01-01  False   True
🔴      luis           2026-03-10  -17   2025-12-10  False   True
⛔      pedro          NEVER       -     2025-06-01  True    False
```
_Total: 5 (mostrando 5)_

---

## 📁 Estructura del proyecto

```
slackbot-ad/
├── app.py              # Aplicación principal Flask + lógica AD
├── requirements.txt    # Dependencias Python
├── .env.example        # Plantilla de variables de entorno
├── .gitignore          # Excluye .env, logs, cachés
└── README.md           # Este fichero
```

---

## 🐛 Debug y Troubleshooting

### Ver OUs detectadas automáticamente

Visita desde el propio servidor:

```
http://localhost:3000/debug
```

Devuelve JSON con todas las OUs y sus DNs completos. Útil para verificar
el nombre exacto a usar en los comandos `ou` y `computers`.

> ⚠️ Elimina o protege el endpoint `/debug` antes de pasar a producción.

### Ver logs del servicio NSSM

```powershell
Get-Content "C:\bots\logs\slackbot.log"       -Tail 50
Get-Content "C:\bots\logs\slackbot_error.log" -Tail 50
```

### Problemas comunes

| Error | Causa probable | Solución |
|---|---|---|
| `OU 'xxx' no encontrada` | Nombre no coincide | Consultar `/debug` para ver nombres exactos |
| `CN=Computers` no aparece | Contenedor builtin, no OU | Añadir manualmente en `get_ou_mapping()` |
| `Invalid signature` | Signing Secret incorrecto | Revisar `.env` |
| `Import-Module ActiveDirectory` falla | RSAT no instalado | `Add-WindowsFeature RSAT-AD-PowerShell` |
| `AccessDenied` al resetear | Falta delegación | Ejecutar script de delegación |
| `AccessDenied` al enable/disable | Falta `Write userAccountControl` | Ejecutar script de delegación |
| Timeout PowerShell | AD con muchos usuarios | Aumentar `timeout=` en la función |
| Tunnel no conecta | Token de cloudflared incorrecto | Reinstalar connector con token correcto |

### Verificar módulo ActiveDirectory

```powershell
Get-Module -ListAvailable ActiveDirectory
# Si no aparece:
Add-WindowsFeature RSAT-AD-PowerShell
```

---

## 🔒 Seguridad

- ✅ **Verificación HMAC-SHA256** de cada petición Slack (previene requests no autorizados)
- ✅ **Ventana de 5 minutos** en el timestamp para prevenir replay attacks
- ✅ **Respuestas `ephemeral`** — solo el usuario que ejecuta el comando ve los resultados
- ✅ **Credenciales en `.env`** — nunca en el código fuente
- ✅ **`.env` excluido del repositorio** via `.gitignore`
- ✅ **Sin puertos abiertos** — el túnel Cloudflare no requiere exponer puertos en el firewall
- ✅ **Confirmación en dos pasos** para acciones destructivas (`disable`, `reset`)
- ✅ **Cuenta de servicio `svc_slackbot`** con permisos mínimos delegados (principio de least privilege)
- ⚠️ Se recomienda ejecutar NSSM con la cuenta de servicio dedicada `svc_slackbot`

---

## 📄 Dependencias (`requirements.txt`)

```
flask>=3.0.0
requests>=2.31.0
python-dotenv>=1.0.0
```

---

## 📜 Licencia

MIT License — libre para uso personal y corporativo.

---

> Desarrollado para **Windows Server 2025** con **Active Directory** y **Cloudflare Tunnel**.
> Tested on: Windows Server 2025 · Python 3.12 · Flask 3.0 · PowerShell 5.1 · cloudflared 2025
