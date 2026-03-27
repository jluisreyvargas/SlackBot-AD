from dotenv import load_dotenv
import os
load_dotenv(r"C:\\bots\\.env")

from flask import Flask, request, jsonify
import subprocess
import hmac
import hashlib
import time
import requests
import threading
import functools

app = Flask(__name__)

SLACK_SIGNING_SECRET = os.environ["SLACK_SIGNING_SECRET"]
SLACK_BOT_TOKEN      = os.environ["SLACK_BOT_TOKEN"]


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


@functools.lru_cache(maxsize=1)
def get_ou_mapping():
    ps_cmd = "Import-Module ActiveDirectory; "
    ps_cmd += "Get-ADObject -Filter {objectClass -eq 'organizationalUnit'} "
    ps_cmd += "-SearchScope Subtree -Properties Name,DistinguishedName | "
    ps_cmd += "Select-Object @{N='Name';E={$_.Name}}, DistinguishedName | "
    ps_cmd += "ConvertTo-Csv -NoTypeInformation"
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
    # AJUSTA DC A TU DOMINIO
    mapping["users"] = "CN=Users,DC=tudominio,DC=local"
    return mapping


def resolve_ou_name(ou_name):
    return get_ou_mapping().get(ou_name.lower().strip())


def get_password_expiry(username):
    sam = username.split("@")[0]
    ps_cmd = (
        "Import-Module ActiveDirectory; "
        f'$u = Get-ADUser -Identity "{sam}" '
        '-Properties @("msDS-UserPasswordExpiryTimeComputed","PasswordNeverExpires","PasswordLastSet"); '
        'if ($u.PasswordNeverExpires) { Write-Output "NEVER" } else { '
        '  $t = $u."msDS-UserPasswordExpiryTimeComputed"; '
        '  if ($t -eq 0 -or $t -eq 9223372036854775807) { Write-Output "NEVER" } else { '
        '    $e = [datetime]::FromFileTime($t); '
        '    $d = ($e - (Get-Date)).Days; '
        '    Write-Output ($e.ToString("yyyy-MM-dd HH:mm") + "|" + $d) '
        '  } '
        '}'
    )
    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", ps_cmd],
        capture_output=True, text=True, timeout=15
    )
    return result.stdout.strip(), result.stderr.strip()


def get_ou_users(ou_dn):
    ps_cmd = (
        "Import-Module ActiveDirectory; "
        f'$users = Get-ADUser -SearchBase "{ou_dn}" -SearchScope Subtree '
        "-Filter {Enabled -eq $true} "
        '-Properties @("msDS-UserPasswordExpiryTimeComputed","PasswordNeverExpires","PasswordLastSet","SamAccountName"); '
        '$users | ForEach-Object { '
        '  $sam = $_.SamAccountName; $never = $_.PasswordNeverExpires; '
        '  $t = $_."msDS-UserPasswordExpiryTimeComputed"; '
        '  if ($never -or $t -eq 0 -or $t -eq 9223372036854775807) { $exp = "NEVER"; $days = "" } '
        '  else { $e = [datetime]::FromFileTime($t); $days = ($e-(Get-Date)).Days; $exp = $e.ToString("yyyy-MM-dd") } '
        '  $ls = if ($_.PasswordLastSet) { $_.PasswordLastSet.ToString("yyyy-MM-dd") } else { "" }; '
        '  Write-Output ($sam + ";" + $exp + ";" + $days + ";" + $ls + ";" + $never) '
        '}'
    )
    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", ps_cmd],
        capture_output=True, text=True, timeout=60
    )
    return result.stdout.strip(), result.stderr.strip()


def get_all_users_expiry():
    ps_cmd = (
        "Import-Module ActiveDirectory; "
        "$users = Get-ADUser -Filter {Enabled -eq $true} "
        '-Properties @("msDS-UserPasswordExpiryTimeComputed","PasswordNeverExpires","PasswordLastSet","SamAccountName"); '
        '$users | ForEach-Object { '
        '  $sam = $_.SamAccountName; $never = $_.PasswordNeverExpires; '
        '  $t = $_."msDS-UserPasswordExpiryTimeComputed"; '
        '  if ($never -or $t -eq 0 -or $t -eq 9223372036854775807) { $exp = "NEVER"; $days = "" } '
        '  else { $e = [datetime]::FromFileTime($t); $days = ($e-(Get-Date)).Days; $exp = $e.ToString("yyyy-MM-dd") } '
        '  $ls = if ($_.PasswordLastSet) { $_.PasswordLastSet.ToString("yyyy-MM-dd") } else { "" }; '
        '  Write-Output ($sam + ";" + $exp + ";" + $days + ";" + $ls + ";" + $never) '
        '}'
    )
    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", ps_cmd],
        capture_output=True, text=True, timeout=120
    )
    return result.stdout.strip(), result.stderr.strip()


def make_md_table(output, title="Usuarios", limit=30):
    rows_raw = [l for l in output.splitlines() if l.strip()]
    if not rows_raw:
        return f"Warning {title}: Sin datos"
    parsed = []
    for line in rows_raw[:limit]:
        if ";" not in line:
            continue
        user, expiry, days, lastset, never = line.split(";")
        days_str = days.strip() or "-"
        try:
            d = int(days_str)
            emoji = "🔴" if d < 0 else "🟠" if d <= 7 else "🟢"
        except ValueError:
            emoji = "🟢" if days_str == "-" else "⚪"
        parsed.append((emoji, user.strip(), expiry.strip(), days_str, lastset.strip(), never.strip()))
    if not parsed:
        return f"Warning {title}: Sin datos"
    headers = ("", "Usuario", "Expira", "Dias", "Ult.Cambio", "Nunca?")
    col_widths = [len(h) for h in headers]
    for row in parsed:
        for i, val in enumerate(row):
            col_widths[i] = max(col_widths[i], len(val))
    def fmt_row(values):
        return "  ".join(str(v).ljust(col_widths[i]) for i, v in enumerate(values))
    separator = "  ".join("-" * w for w in col_widths)
    table_lines = [fmt_row(headers), separator]
    for row in parsed:
        table_lines.append(fmt_row(row))
    table_str = "\n".join(table_lines)
    total_str = f"Total: {len(rows_raw)} usuarios (mostrando {min(len(rows_raw), limit)})"
    return f"*{title}*\n```\n{table_str}\n```\n_{total_str}_"


def process_user(username, response_url):
    output, error = get_password_expiry(username)
    if error:
        msg = f"Error consultando AD:\n```{error}```"
    elif output == "NEVER":
        msg = f"La contrasena de `{username}` *nunca caduca*."
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
        msg = f"Usuario `{username}` no encontrado en AD."
    requests.post(response_url, json={"response_type": "ephemeral", "text": msg})


def process_ou(ou_dn, ou_name, response_url):
    output, error = get_ou_users(ou_dn)
    msg = f"Error en OU {ou_name}:\n```{error}```" if error else make_md_table(output, f"OU '{ou_name}'")
    requests.post(response_url, json={"response_type": "ephemeral", "text": msg})


def process_all(response_url):
    output, error = get_all_users_expiry()
    msg = f"Error listando usuarios:\n```{error}```" if error else make_md_table(output, "TODOS usuarios habilitados")
    requests.post(response_url, json={"response_type": "ephemeral", "text": msg})


@app.route("/slack/events", methods=["POST"])
def slack_events():
    if not verify_slack_signature(request):
        return jsonify({"error": "Invalid signature"}), 403
    text         = request.form.get("text", "").strip()
    response_url = request.form.get("response_url")
    if not text:
        ous = ", ".join(sorted(get_ou_mapping().keys()))
        help_text = (
            "Comandos disponibles:\n"
            "- /checkpass usuario@dominio.local\n"
            "- /checkpass ou <nombre>\n"
            "- /checkpass all\n\n"
            f"OUs disponibles: {ous}"
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
    else:
        return jsonify({"response_type": "ephemeral", "text": "Comando no reconocido. Escribe /checkpass para ver la ayuda."})
    return jsonify({"response_type": "ephemeral", "text": "Consultando Active Directory..."})


@app.route("/debug")
def debug():
    return jsonify({"ous": dict(get_ou_mapping())})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3000, debug=False)
