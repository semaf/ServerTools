import logging
import requests
import redis
import time
import re
from datetime import timedelta
from dotenv import load_dotenv
import os

# Logging konfigurieren
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Lade Umgebungsvariablen aus der .env-Datei
load_dotenv()

# Konfigurationen aus .env
CROWDSEC_API_KEY = os.getenv("CROWDSEC_API_KEY")
CROWDSEC_API_URL = os.getenv("CROWDSEC_API_URL")
CLOUDFLARE_API_KEY = os.getenv("CLOUDFLARE_API_KEY")
CLOUDFLARE_ZONE_ID = os.getenv("CLOUDFLARE_ZONE_ID")
CLOUDFLARE_FILTER_ID = os.getenv("CLOUDFLARE_FILTER_ID")
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD")
CLOUDFLARE_FILTER_URL = f"https://api.cloudflare.com/client/v4/zones/{CLOUDFLARE_ZONE_ID}/filters/{CLOUDFLARE_FILTER_ID}"

REDIS_HOST = "localhost"
REDIS_PORT = 6379
EXPIRATION_TIME = 86400 * 7  # 7 Tage in Sekunden

# Redis-Client initialisieren
try:
    redis_client = redis.StrictRedis(
        host=REDIS_HOST,
        port=REDIS_PORT,
        password=REDIS_PASSWORD,
        decode_responses=True
    )
    redis_client.ping()
    logger.info("Verbindung zu Redis erfolgreich.")
except redis.ConnectionError as e:
    logger.error(f"Fehler bei der Verbindung zu Redis: {e}")
    exit(1)


def fetch_crowdsec_alerts(threshold=10):
    """Ruft gebannte IPs aus CrowdSec ab, die häufiger als das Threshold gebannt wurden."""
    headers = {"X-Api-Key": CROWDSEC_API_KEY}
    try:
        response = requests.get(CROWDSEC_API_URL, headers=headers)
        response.raise_for_status()
        alerts = response.json()

        # Zähle Bann-Ereignisse
        ip_ban_count = {}
        for alert in alerts:
            ip = alert["value"]
            if ip not in ip_ban_count:
                ip_ban_count[ip] = 0
            ip_ban_count[ip] += 1

        # Filtere nur IPs, die das Threshold überschreiten
        frequent_banned_ips = [ip for ip, count in ip_ban_count.items() if count >= threshold]
        return frequent_banned_ips
    except requests.RequestException as e:
        logger.error(f"Fehler beim Abrufen der CrowdSec-Alerts: {e}")
        return []


def fetch_cloudflare_expression():
    """Holt die aktuelle Expression von Cloudflare."""
    headers = {"Authorization": f"Bearer {CLOUDFLARE_API_KEY}"}
    try:
        response = requests.get(CLOUDFLARE_FILTER_URL, headers=headers)
        response.raise_for_status()
        expression = response.json()["result"]["expression"]
        logger.info(f"Aktuelle Expression von Cloudflare: {expression}")
        return expression
    except requests.RequestException as e:
        logger.error(f"Fehler beim Abrufen der Cloudflare-Expression: {e}")
        return ""


def parse_expression(expression):
    """Parst die bestehende Expression in Bedingungen und IP-Liste."""
    ip_list_match = re.search(r"ip\.src in \{([^}]*)\}", expression)
    existing_ips = set(ip_list_match.group(1).replace(",", "").split()) if ip_list_match else set()
    other_conditions = re.sub(r"ip\.src in \{[^}]*\}", "", expression).strip()

    # Speichere die Bedingungen in Redis
    if other_conditions:
        redis_client.set("cloudflare:conditions", other_conditions)
    else:
        # Lade Bedingungen aus Redis, wenn keine gefunden wurden
        other_conditions = redis_client.get("cloudflare:conditions") or ""

    return existing_ips, other_conditions


def build_expression(countries, ip_list):
    """
    Baut die Cloudflare-Expression dynamisch aus den gegebenen Länderbedingungen und IPs.
    :param countries: Liste der Ländercodes (z. B. ["CN", "RU"])
    :param ip_list: Liste der IP-Adressen
    :return: Fertige Cloudflare-Expression als String
    """
    # Baue die Bedingungen für Länder
    country_conditions = [f'(ip.geoip.country eq "{country}")' for country in countries]

    # Baue die Bedingung für IPs
    # Entferne Leerzeichen und trenne IPs korrekt mit Kommas
    formatted_ips = " ".join(sorted(ip_list))  # Sortieren für konsistente Ordnung
    ip_condition = f'(ip.src in {{ {formatted_ips} }})' if ip_list else ""

    # Kombiniere alle Bedingungen mit 'or'
    all_conditions = country_conditions + ([ip_condition] if ip_condition else [])
    final_expression = " or ".join(filter(None, all_conditions))

    return final_expression


def synchronize_with_cloudflare():
    """
    Synchronisiert die aktuelle Cloudflare-Expression mit Redis.
    """
    expression = fetch_cloudflare_expression()
    if not expression:
        logger.error("Konnte die aktuelle Cloudflare-Expression nicht abrufen.")
        return

    # Parse die Expression
    existing_ips, other_conditions = parse_expression(expression)

    # Speichere Länderbedingungen in Redis
    if other_conditions:
        redis_client.set("cloudflare:conditions", other_conditions)

    # Speichere bestehende IPs in Redis
    for ip in existing_ips:
        redis_client.setex(f"cloudflare:{ip}", EXPIRATION_TIME, 1)

    logger.info("Cloudflare-Expression erfolgreich mit Redis synchronisiert.")


def update_cloudflare_expression(new_ips):
    """
    Aktualisiert die Cloudflare-Expression, indem sie bestehende Bedingungen liest und neue IPs hinzufügt.
    """
    # Synchronisiere zuerst Redis mit der aktuellen Cloudflare-Expression
    synchronize_with_cloudflare()

    # Lade Länderbedingungen aus Redis
    countries_condition = redis_client.get("cloudflare:conditions")
    countries = {match.group(1) for match in re.finditer(r'ip\.geoip\.country eq "([^"]+)"', countries_condition)} if countries_condition else set()
    if not countries:
        logger.warning("Keine Länderbedingungen in Redis gefunden. Standardbedingungen werden verwendet.")
        countries = {"CN", "RU"}  # Fallback

    # Lade bestehende IPs aus Redis
    existing_ips = set()
    for key in redis_client.scan_iter("cloudflare:*"):
        ip = key.replace("cloudflare:", "")
        if redis_client.ttl(key) > 0:  # Nur gültige IPs verwenden
            existing_ips.add(ip)

    # Entferne abgelaufene IPs
    for ip in list(existing_ips):
        if redis_client.ttl(f"cloudflare:{ip}") < 0:
            existing_ips.remove(ip)
            redis_client.delete(f"cloudflare:{ip}")

    # Füge neue IPs hinzu
    updated_ips = existing_ips.union(new_ips)
    for ip in new_ips:
        redis_client.setex(f"cloudflare:{ip}", EXPIRATION_TIME, 1)

    # Baue die Expression neu
    final_expression = build_expression(countries, updated_ips)

    # Prüfe die Länge der Expression
    if len(final_expression) > 4096:  # Annahme: Cloudflare-Limit liegt bei 4096 Zeichen
        logger.error("Die Expression ist zu lang für Cloudflare.")
        return

    # Sende die Expression an Cloudflare
    headers = {
        "Authorization": f"Bearer {CLOUDFLARE_API_KEY}",
        "Content-Type": "application/json"
    }
    payload = {
        "expression": final_expression,
        "paused": False,
        "description": "Automatisch aktualisierte IP-Liste"
    }

    logger.info(f"Payload wird an Cloudflare gesendet: {payload}")

    try:
        response = requests.put(CLOUDFLARE_FILTER_URL, json=payload, headers=headers)
        response.raise_for_status()
        logger.info("Cloudflare-Expression erfolgreich aktualisiert.")
    except requests.RequestException as e:
        if hasattr(e.response, 'text'):
            logger.error(f"Cloudflare-Fehlerantwort: {e.response.text}")
        logger.error(f"Fehler beim Aktualisieren der Cloudflare-Expression: {e}")


def process_alerts():
    """Verarbeitet Alerts von CrowdSec und aktualisiert Cloudflare."""
    new_ips = fetch_crowdsec_alerts(threshold=10)
    if new_ips:
        logger.info(f"{len(new_ips)} neue IPs aus CrowdSec abgerufen, die mehr als 10 Mal gebannt wurden.")
        update_cloudflare_expression(new_ips)
    else:
        logger.info("Keine neuen IPs zum Aktualisieren.")


if __name__ == "__main__":
    process_alerts()
