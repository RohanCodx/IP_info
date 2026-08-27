import ipaddress
import sys
from concurrent.futures import ThreadPoolExecutor

import requests

print("made by RohanCodx")
print("=" * 45 + "\n      SHORT & KEYLESS IP ANALYZER\n" + "=" * 45)

try:
    ip = input("\nEnter IPv6 Address (blank = your own IP): ").strip()
except (EOFError, KeyboardInterrupt):
    sys.exit("\nCancelled.")

# Validate input early instead of sending garbage to the APIs
if ip:
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        sys.exit(f"'{ip}' is not a valid IP address.")

headers = {"User-Agent": "Mozilla/5.0"}
session = requests.Session()
ipapi, ipwhois = {}, {}


def fetch_ipapi():
    fields = "status,message,country,regionName,city,isp,proxy,hosting,mobile"
    url = f"http://ip-api.com/json/{ip}?fields={fields}"
    resp = session.get(url, headers=headers, timeout=5)
    resp.raise_for_status()
    return resp.json()


def fetch_ipwhois():
    url = f"https://ipwho.is/{ip}"
    resp = session.get(url, headers=headers, timeout=5)
    resp.raise_for_status()
    return resp.json()

# Run both lookups concurrently instead of one after another
with ThreadPoolExecutor(max_workers=2) as pool:
    fut_ipapi = pool.submit(fetch_ipapi)
    fut_ipwhois = pool.submit(fetch_ipwhois)

    try:
        ipapi = fut_ipapi.result()
    except requests.RequestException:
        pass

    try:
        ipwhois = fut_ipwhois.result()
    except requests.RequestException:
        pass

ipapi_ok = ipapi.get("status") == "success"
ipwhois_ok = ipwhois.get("success") is True

# Tell the user plainly if both sources failed instead of quietly
# printing an all-"Unknown", falsely reassuring "LOW risk" report.
if not ipapi_ok and not ipwhois_ok:
    reason = ipapi.get("message") or "both lookups failed or the IP could not be resolved"
    sys.exit(f"\nCould not retrieve data for '{ip}': {reason}")

# Determine fallback data sets
d_geo = ipapi if ipapi_ok else ipwhois
d_sec = ipwhois.get("security", {}) if ipwhois_ok else {}
d_conn = ipwhois.get("connection", {}) if ipwhois_ok else {}

resolved_ip = d_geo.get("query") or d_geo.get("ip") or (ip or "your IP")

# Extract Geolocation parameters safely
city = d_geo.get("city", "Unknown")
region = d_geo.get("regionName", d_geo.get("region", "Unknown"))
country = d_geo.get("country", "Unknown")

# Extract ISP text smoothly without crashing
isp = "Unknown"
if isinstance(d_geo.get("isp"), str):
    isp = d_geo["isp"]
elif isinstance(d_geo.get("connection"), dict):
    isp = d_geo["connection"].get("isp", "Unknown")

# Consolidate Security Threat Vectors
vpn = bool(ipapi.get("proxy") or d_sec.get("vpn") or d_sec.get("proxy"))
tor = bool(d_sec.get("tor"))
hosting = bool(ipapi.get("hosting") or d_sec.get("hosting"))
# Fall back to ipwho.is's connection type when ip-api didn't answer
mobile = bool(ipapi.get("mobile")) if ipapi_ok else str(d_conn.get("type", "")).lower() == "mobile"

# Dynamic Risk Score Engine (capped at 100, Tor weighted highest)
risk_score = min(100, (45 if tor else 0) + (35 if vpn else 0) + (20 if hosting else 0))
if risk_score >= 70:
    verdict = "🔴 HIGH"
elif risk_score >= 30:
    verdict = "🟡 MEDIUM"
else:
    verdict = "🟢 LOW"

# Output Final Consolidated Report
print(f"\n🌍 Target IP    : {resolved_ip}")
print(f"🌎 Location     : {city}, {region}, {country}")
print(f"📡 Network ISP  : {isp}")

print("\n" + "-" * 15 + " SECURITY TRACKS " + "-" * 14)
print(f"🛡️  VPN / Proxy Active : {vpn}")
print(f"🧅 Tor Exit Node       : {tor}")
print(f"☁️  Data Center Host   : {hosting}")
print(f"📱 Mobile Data Carrier : {mobile}")
print(f"🚨 Risk Verdict        : {risk_score}/100 ({verdict})")
if not (ipapi_ok and ipwhois_ok):
    source = "ip-api.com only" if ipapi_ok else "ipwho.is only"
    print(f"ℹ️  Note: one data source was unavailable — results based on {source}")
print("=" * 45)
