from dotenv import load_dotenv
import os
load_dotenv(r"C:\bots\.env")

from flask import Flask, request, jsonify
import subprocess
import hmac
import hashlib
import time
import requests
import threading
import functools
import secrets
import string

app = Flask(__name__)

SLACK_SIGNING_SECRET = os.environ["SLACK_SIGNING_SECRET"]
SLACK_BOT_TOKEN      = os.environ["SLACK_BOT_TOKEN"]


# ─── VERIFICACION FIRMA SLACK ──────────────────────────────────────────────
def verify_slack_signature(req):
    timestamp = req.headers.get("X-Slack-Request-Timestamp", "")
    if abs(time.time() - int(timestamp)) > 60 * 5:
        return False
    sig_basestring = f"v0:{timestamp}:{req.get_data(as_text=True)}"
    my_signature = "v0=" + hmac.new(
        SLACK_SIGNING_SECRET.encode(),
        sig_basestring.encode(),
        hashlib.sha256
    ).hexdigest()
    slack_signature = req.headers.get("X-Slack-Signature", "")
    return hmac.compare_digest(my_signature, slack_signature)


# ─── CACHE OUs ─────────────────────────────────────────────────────────────
@functools.lru_cache(maxsize=1)
def get_ou_mapping():
    ps_cmd = (
        "Import-Module ActiveDirectory; "
        "Get-ADObject -Filter {objectClass -eq 'organizationalUnit'} "
        "-SearchScope Subtree -Properties Name,DistinguishedName | "
        "Select-Object @{N='Name';E={$_.Name}}, DistinguishedName | "
        "ConvertTo-Csv -NoTypeInformation"
    )
    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", ps_cmd],
        capture_output=True, text=True, timeout=30
    )
    mapping = {}
    if not result.stderr:
        for line in result.stdout.strip().splitlines()[1:]:
            if line and ',"' in line:
                parts = line.split('","', 1)
                if len(parts) == 2:
                    name = parts[0].strip('"').lower().strip()
                    dn   = parts[1].rstrip().strip('"')
                    if name and dn:
                        mapping[name] = dn
    # Contenedores builtin (no son OUs reales) — AJUSTA A TU DOMINIO
    mapping["users"]     = "CN=Users,DC=tudominio,DC=local"
    mapping["computers"] = "CN=Computers,DC=tudominio,DC=local"
    return mapping


def resolve_ou_name(ou_name):
    return get_ou_mapping().get(ou_name.lower().strip())


# ─── UTILIDADES ─────────────────────────────────────────────────────────────
def generate_temp_password(length=12):
    chars = string.ascii_uppercase + string.ascii_lowercase + string.digits + "!@#$%&*"
    while True:
        pwd = "".join(secrets.choice(chars) for _ in range(length))
        if (any(c.isupper() for c in pwd) and
            any(c.islower() for c in pwd) and
            any(c.isdigit() for c in pwd) and
            any(c in "!@#$%&*" for c in pwd)):
            return pwd


def make_md_table(output, title="Usuarios", limit=30):
    rows_raw = [l for l in output.splitlines() if l.strip()]
    if not rows_raw:
        return f"Sin datos en {title}"
    parsed = []
    for line in rows_raw[:limit]:
        if ";" not in line:
            continue
        fields = line.split(";")
        if len(fields) < 6:
            continue
        user, expiry, days, lastset, never, enabled = fields[:6]
        days_str    = days.strip() or "-"
        enabled_str = enabled.strip()
        if enabled_str == "False":
            estado = "DISABLED"
        else:
            try:
                d = int(days_str)
                estado = "EXPIRED" if d < 0 else "WARN" if d <= 7 else "OK"
            except ValueError:
                estado = "OK"
        emoji_map = {"OK": "🟢", "WARN": "🟠", "EXPIRED": "🔴", "DISABLED": "⛔"}
        emoji = emoji_map.get(estado, "⚪")
        parsed.append((emoji, user.strip(), expiry.strip(), days_str,
                       lastset.strip(), never.strip(), enabled_str))
    if not parsed:
        return f"Sin datos en {title}"
    headers = ("", "Usuario", "Expira", "Dias", "Ult.Cambio", "Nunca?", "Activo?")
    col_widths = [len(h) for h in headers]
    for row in parsed:
        for i, val in enumerate(row):
            col_widths[i] = max(col_widths[i], len(val))
    def fmt_row(values):
        return "  ".join(str(v).ljust(col_widths[i]) for i, v in enumerate(values))
    separator = "  ".join("-" * w for w in col_widths)
    table     = "\n".join([fmt_row(headers), separator] + [fmt_row(r) for r in parsed])
    total     = f"Total: {len(rows_raw)} (mostrando {min(len(rows_raw), limit)})"
    return f"*{title}*\n```\n{table}\n```\n_{total}_"


# ─── POWERSHELL: usuario individual ────────────────────────────────────────
def get_password_expiry(username):
    sam = username.split("@")[0]
    ps_cmd = (
        "Import-Module ActiveDirectory; "
        f"$u = Get-ADUser -Identity '{sam}' "
        "-Properties @('msDS-UserPasswordExpiryTimeComputed','PasswordNeverExpires','PasswordLastSet'); "
        "if ($u.PasswordNeverExpires) { Write-Output 'NEVER' } else { "
        "  $t = $u.'msDS-UserPasswordExpiryTimeComputed'; "
        "  if ($t -eq 0 -or $t -eq 9223372036854775807) { Write-Output 'NEVER' } else { "
        "    $e = [datetime]::FromFileTime($t); $d = ($e - (Get-Date)).Days; "
        "    Write-Output ($e.ToString('yyyy-MM-dd HH:mm') + '|' + $d) } }"
    )
    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", ps_cmd],
        capture_output=True, text=True, timeout=15
    )
    return result.stdout.strip(), result.stderr.strip()


# ─── POWERSHELL: usuarios de una OU (incluye deshabilitados) ─────────────────
def get_ou_users(ou_dn):
    ps_cmd = (
        "Import-Module ActiveDirectory; "
        f"$users = Get-ADUser -SearchBase '{ou_dn}' -SearchScope Subtree "
        "-Filter * "
        "-Properties @('msDS-UserPasswordExpiryTimeComputed','PasswordNeverExpires','PasswordLastSet','SamAccountName','Enabled'); "
        "$users | ForEach-Object { "
        "  $sam = $_.SamAccountName; $never = $_.PasswordNeverExpires; $enabled = $_.Enabled; "
        "  $t = $_.'msDS-UserPasswordExpiryTimeComputed'; "
        "  if ($never -or $t -eq 0 -or $t -eq 9223372036854775807) { $exp = 'NEVER'; $days = '' } "
        "  else { $e = [datetime]::FromFileTime($t); $days = ($e-(Get-Date)).Days; $exp = $e.ToString('yyyy-MM-dd') } "
        "  $ls = if ($_.PasswordLastSet) { $_.PasswordLastSet.ToString('yyyy-MM-dd') } else { '' }; "
        "  Write-Output ($sam+';'+$exp+';'+$days+';'+$ls+';'+$never+';'+$enabled) }"
    )
    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", ps_cmd],
        capture_output=True, text=True, timeout=60
    )
    return result.stdout.strip(), result.stderr.strip()


# ─── POWERSHELL: todos los usuarios (incluye deshabilitados) ─────────────────
def get_all_users_expiry():
    ps_cmd = (
        "Import-Module ActiveDirectory; "
        "$users = Get-ADUser -Filter * "
        "-Properties @('msDS-UserPasswordExpiryTimeComputed','PasswordNeverExpires','PasswordLastSet','SamAccountName','Enabled'); "
        "$users | ForEach-Object { "
        "  $sam = $_.SamAccountName; $never = $_.PasswordNeverExpires; $enabled = $_.Enabled; "
        "  $t = $_.'msDS-UserPasswordExpiryTimeComputed'; "
        "  if ($never -or $t -eq 0 -or $t -eq 9223372036854775807) { $exp = 'NEVER'; $days = '' } "
        "  else { $e = [datetime]::FromFileTime($t); $days = ($e-(Get-Date)).Days; $exp = $e.ToString('yyyy-MM-dd') } "
        "  $ls = if ($_.PasswordLastSet) { $_.PasswordLastSet.ToString('yyyy-MM-dd') } else { '' }; "
        "  Write-Output ($sam+';'+$exp+';'+$days+';'+$ls+';'+$never+';'+$enabled) }"
    )
    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", ps_cmd],
        capture_output=True, text=True, timeout=120
    )
    return result.stdout.strip(), result.stderr.strip()


# ─── POWERSHELL: equipos de una OU (incluye deshabilitados) ──────────────────
def get_ou_computers(ou_dn):
    ps_cmd = (
        "Import-Module ActiveDirectory; "
        f"$computers = Get-ADComputer -SearchBase '{ou_dn}' -SearchScope Subtree "
        "-Filter * "
        "-Properties @('Name','OperatingSystem','IPv4Address','LastLogonDate','Enabled'); "
        "$computers | ForEach-Object { "
        "  $ll = if ($_.LastLogonDate) { $_.LastLogonDate.ToString('yyyy-MM-dd') } else { 'Nunca' }; "
        "  $os = if ($_.OperatingSystem) { $_.OperatingSystem } else { 'Desconocido' }; "
        "  $ip = if ($_.IPv4Address) { $_.IPv4Address } else { '' }; "
        "  $enabled = $_.Enabled; "
        "  Write-Output ($_.Name+';'+$os+';'+$ip+';'+$ll+';'+$enabled) }"
    )
    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", ps_cmd],
        capture_output=True, text=True, timeout=60
    )
    return result.stdout.strip(), result.stderr.strip()


# ─── POWERSHELL: reset contraseña ───────────────────────────────────────────
def reset_user_password(username):
    sam = username.split("@")[0]
    temp_password = generate_temp_password()
    ps_cmd = (
        "Import-Module ActiveDirectory; "
        f"$u = Get-ADUser -Identity '{sam}' -Properties Enabled -ErrorAction SilentlyContinue; "
        "if (-not $u) { Write-Output 'NOTFOUND'; exit }; "
        "if (-not $u.Enabled) { Write-Output 'DISABLED'; exit }; "
        f"Set-ADAccountPassword -Identity '{sam}' -Reset "
        f"-NewPassword (ConvertTo-SecureString -AsPlainText '{temp_password}' -Force); "
        f"Set-ADUser -Identity '{sam}' -ChangePasswordAtLogon $true; "
        "Write-Output 'OK'"
    )
    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", ps_cmd],
        capture_output=True, text=True, timeout=15
    )
    return result.stdout.strip(), result.stderr.strip(), temp_password


# ─── POWERSHELL: habilitar / deshabilitar cuenta ─────────────────────────────
def set_user_enabled(username, enable: bool):
    sam    = username.split("@")[0]
    action = "true" if enable else "false"
    ps_cmd = (
        "Import-Module ActiveDirectory; "
        f"$u = Get-ADUser -Identity '{sam}' -ErrorAction SilentlyContinue; "
        "if (-not $u) { Write-Output 'NOTFOUND'; exit }; "
        f"Set-ADUser -Identity '{sam}' -Enabled ${action}; "
        "Write-Output 'OK'"
    )
    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", ps_cmd],
        capture_output=True, text=True, timeout=15
    )
    return result.stdout.strip(), result.stderr.strip()


# ─── HANDLERS ───────────────────────────────────────────────────────────────
def process_user(username, response_url):
    output, error = get_password_expiry(username)
    if error:
        msg = f"Error consultando AD:\n```{error}```"
    elif output == "NEVER":
        msg = f"🟢 `{username}` — La contrasena *nunca caduca*."
    elif "|" in output:
        expires_str, days = output.split("|")
        days = int(days)
        if days < 0:
            emoji, status = "🔴", f"*CADUCADA* hace {abs(days)} dias"
        elif days <= 7:
            emoji, status = "🟠", f"caduca en *{days} dias* ({expires_str})"
        else:
            emoji, status = "🟢", f"caduca el *{expires_str}* (en {days} dias)"
        msg = f"{emoji} `{username}` — {status}."
    else:
        msg = f"⚠️ Usuario `{username}` no encontrado en AD."
    requests.post(response_url, json={"response_type": "ephemeral", "text": msg})


def process_ou(ou_dn, ou_name, response_url):
    output, error = get_ou_users(ou_dn)
    msg = f"❌ Error en OU {ou_name}:\n```{error}```" if error else make_md_table(output, f"OU '{ou_name}'")
    requests.post(response_url, json={"response_type": "ephemeral", "text": msg})


def process_all(response_url):
    output, error = get_all_users_expiry()
    msg = f"❌ Error listando usuarios:\n```{error}```" if error else make_md_table(output, "TODOS los usuarios")
    requests.post(response_url, json={"response_type": "ephemeral", "text": msg})


def process_ou_computers(ou_dn, ou_name, response_url):
    output, error = get_ou_computers(ou_dn)
    if error:
        msg = f"❌ Error listando equipos en '{ou_name}':\n```{error}```"
    elif not output:
        msg = f"⚠️ No hay equipos en OU '{ou_name}'."
    else:
        rows_raw = [l for l in output.splitlines() if l.strip()]
        headers  = ("", "Nombre", "Sistema Operativo", "IP", "Ultimo Login")
        col_widths = [len(h) for h in headers]
        parsed = []
        for line in rows_raw[:30]:
            if ";" not in line:
                continue
            fields = line.split(";")
            if len(fields) < 5:
                continue
            name, os_name, ip, last, enabled = fields[:5]
            emoji = "⛔" if enabled.strip() == "False" else "🟢"
            row = (emoji, name.strip(), os_name.strip()[:32], ip.strip(), last.strip())
            parsed.append(row)
            for i, val in enumerate(row):
                col_widths[i] = max(col_widths[i], len(val))
        def fmt_row(values):
            return "  ".join(str(v).ljust(col_widths[i]) for i, v in enumerate(values))
        sep   = "  ".join("-" * w for w in col_widths)
        table = "\n".join([fmt_row(headers), sep] + [fmt_row(r) for r in parsed])
        msg   = (
            f"*Equipos en OU '{ou_name}'*\n"
            f"```\n{table}\n```\n"
            f"_Total: {len(rows_raw)} equipos_"
        )
    requests.post(response_url, json={"response_type": "ephemeral", "text": msg})


def process_reset(username, response_url):
    output, error, temp_pwd = reset_user_password(username)
    if error and "AccessDenied" in error:
        msg = (
            f"❌ `svc_slackbot` no tiene permisos para resetear `{username}`.\n"
            "Delega el permiso *Reset Password* en la OU correspondiente."
        )
    elif error:
        msg = f"❌ Error reseteando contrasena:\n```{error}```"
    elif output == "NOTFOUND":
        msg = f"⚠️ Usuario `{username}` no encontrado en AD."
    elif output == "DISABLED":
        msg = (
            f"⚠️ La cuenta `{username}` esta *deshabilitada*.\n"
            f"Habilítala primero con: `/checkpass enable {username}`"
        )
    elif output == "OK":
        msg = (
            f"🔑 Contrasena de `{username}` reseteada correctamente.\n"
            f"• Contrasena temporal: `{temp_pwd}`\n"
            "• El usuario debera cambiarla en el proximo inicio de sesion."
        )
    else:
        msg = f"⚠️ Respuesta inesperada: `{output}`"
    requests.post(response_url, json={"response_type": "ephemeral", "text": msg})


def process_enable(username, response_url):
    output, error = set_user_enabled(username, enable=True)
    if error and "AccessDenied" in error:
        msg = (
            f"❌ `svc_slackbot` no tiene permisos para habilitar `{username}`.\n"
            "Delega *Write userAccountControl* en la OU correspondiente."
        )
    elif error:
        msg = f"❌ Error habilitando cuenta:\n```{error}```"
    elif output == "NOTFOUND":
        msg = f"⚠️ Usuario `{username}` no encontrado en AD."
    elif output == "OK":
        msg = f"✅ Cuenta `{username}` *habilitada* correctamente."
    else:
        msg = f"⚠️ Respuesta inesperada: `{output}`"
    requests.post(response_url, json={"response_type": "ephemeral", "text": msg})


def process_disable(username, response_url):
    output, error = set_user_enabled(username, enable=False)
    if error and "AccessDenied" in error:
        msg = (
            f"❌ `svc_slackbot` no tiene permisos para deshabilitar `{username}`.\n"
            "Delega *Write userAccountControl* en la OU correspondiente."
        )
    elif error:
        msg = f"❌ Error deshabilitando cuenta:\n```{error}```"
    elif output == "NOTFOUND":
        msg = f"⚠️ Usuario `{username}` no encontrado en AD."
    elif output == "OK":
        msg = f"⛔ Cuenta `{username}` *deshabilitada* correctamente."
    else:
        msg = f"⚠️ Respuesta inesperada: `{output}`"
    requests.post(response_url, json={"response_type": "ephemeral", "text": msg})


# ─── RUTA PRINCIPAL SLACK ───────────────────────────────────────────────────
@app.route("/slack/events", methods=["POST"])
def slack_events():
    if not verify_slack_signature(request):
        return jsonify({"error": "Invalid signature"}), 403

    text         = request.form.get("text", "").strip()
    response_url = request.form.get("response_url")

    if not text:
        ous = ", ".join(sorted(get_ou_mapping().keys()))
        help_text = (
            "🔧 *Comandos disponibles:*\n"
            "• `/checkpass usuario@dominio` — Caducidad de contrasena\n"
            "• `/checkpass ou <nombre>` — Usuarios de una OU (todos)\n"
            "• `/checkpass all` — Todos los usuarios del AD\n"
            "• `/checkpass computers <nombre>` — Equipos de una OU\n"
            "• `/checkpass reset usuario@dominio` — Solicitar reset de contrasena\n"
            "• `/checkpass resetconfirm usuario@dominio` — Confirmar reset\n"
            "• `/checkpass enable usuario@dominio` — Habilitar cuenta\n"
            "• `/checkpass disable usuario@dominio` — Solicitar deshabilitar cuenta\n"
            "• `/checkpass disableconfirm usuario@dominio` — Confirmar deshabilitar\n\n"
            "Leyenda: 🟢 Activo OK  🟠 Caduca pronto  🔴 Caducada  ⛔ Deshabilitado\n\n"
            f"*OUs disponibles:* {ous}"
        )
        return jsonify({"response_type": "ephemeral", "text": help_text})

    parts = text.split(maxsplit=1)
    cmd   = parts[0].lower()

    if "@" in cmd and len(parts) == 1:
        threading.Thread(target=process_user, args=(cmd, response_url)).start()

    elif cmd == "ou":
        if len(parts) < 2:
            ous = ", ".join(sorted(get_ou_mapping().keys()))
            return jsonify({"response_type": "ephemeral", "text": f"Indica la OU. Disponibles: {ous}"})
        ou_name = parts[1].strip()
        ou_dn   = resolve_ou_name(ou_name)
        if not ou_dn:
            ous = ", ".join(sorted(get_ou_mapping().keys()))
            return jsonify({"response_type": "ephemeral", "text": f"OU '{ou_name}' no encontrada. Disponibles: {ous}"})
        threading.Thread(target=process_ou, args=(ou_dn, ou_name, response_url)).start()

    elif cmd == "all":
        threading.Thread(target=process_all, args=(response_url,)).start()

    elif cmd == "computers":
        if len(parts) < 2:
            ous = ", ".join(sorted(get_ou_mapping().keys()))
            return jsonify({"response_type": "ephemeral", "text": f"Indica la OU. Disponibles: {ous}"})
        ou_name = parts[1].strip()
        ou_dn   = resolve_ou_name(ou_name)
        if not ou_dn:
            ous = ", ".join(sorted(get_ou_mapping().keys()))
            return jsonify({"response_type": "ephemeral", "text": f"OU '{ou_name}' no encontrada. Disponibles: {ous}"})
        threading.Thread(target=process_ou_computers, args=(ou_dn, ou_name, response_url)).start()

    elif cmd == "reset":
        if len(parts) < 2:
            return jsonify({"response_type": "ephemeral", "text": "Uso: /checkpass reset usuario@dominio.local"})
        target_user = parts[1].strip()
        return jsonify({"response_type": "ephemeral", "text": (
            f"⚠️ Vas a resetear la contrasena de `{target_user}`.\n"
            f"Escribe `/checkpass resetconfirm {target_user}` para confirmar."
        )})

    elif cmd == "resetconfirm":
        if len(parts) < 2:
            return jsonify({"response_type": "ephemeral", "text": "Uso: /checkpass resetconfirm usuario@dominio.local"})
        target_user = parts[1].strip()
        threading.Thread(target=process_reset, args=(target_user, response_url)).start()

    elif cmd == "enable":
        if len(parts) < 2:
            return jsonify({"response_type": "ephemeral", "text": "Uso: /checkpass enable usuario@dominio.local"})
        target_user = parts[1].strip()
        threading.Thread(target=process_enable, args=(target_user, response_url)).start()

    elif cmd == "disable":
        if len(parts) < 2:
            return jsonify({"response_type": "ephemeral", "text": "Uso: /checkpass disable usuario@dominio.local"})
        target_user = parts[1].strip()
        return jsonify({"response_type": "ephemeral", "text": (
            f"⚠️ Vas a *deshabilitar* la cuenta `{target_user}`.\n"
            f"Escribe `/checkpass disableconfirm {target_user}` para confirmar."
        )})

    elif cmd == "disableconfirm":
        if len(parts) < 2:
            return jsonify({"response_type": "ephemeral", "text": "Uso: /checkpass disableconfirm usuario@dominio.local"})
        target_user = parts[1].strip()
        threading.Thread(target=process_disable, args=(target_user, response_url)).start()

    else:
        return jsonify({"response_type": "ephemeral",
                        "text": "❓ Comando no reconocido. Escribe `/checkpass` para ver la ayuda."})

    return jsonify({"response_type": "ephemeral", "text": "🔍 Consultando Active Directory..."})


# ─── DEBUG (desactivar en produccion) ───────────────────────────────────────
@app.route("/debug")
def debug():
    return jsonify({"ous": dict(get_ou_mapping())})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3000, debug=False)