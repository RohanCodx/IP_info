import requests
print("made by RohanCodx")
print("=" * 45 + "\n      SHORT & KEYLESS IP ANALYZER\n" + "=" * 45)
ip = input("\nEnter IP Address: ").strip()

headers = {"User-Agent": "Mozilla/5.0"}
ipapi, ipwhois = {}, {}

# Fetch data safely with try/except blocks to prevent connection crashes
try:
    r1 = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,proxy,hosting,mobile", headers=headers, timeout=5)
    if r1.status_code == 200: 
        ipapi = r1.json()
except: 
    pass

try:
    r2 = requests.get(f"https://ipwho.is/{ip}", headers=headers, timeout=5)
    if r2.status_code == 200: 
        ipwhois = r2.json()
except: 
    pass

# Determine fallback data sets
d_geo = ipapi if ipapi.get("status") == "success" else ipwhois
d_sec = ipwhois.get("security", {}) if ipwhois.get("success") is True else {}

# Extract Geolocation parameters safely
city = d_geo.get("city", "Unknown")
region = d_geo.get("regionName", d_geo.get("region", "Unknown"))
country = d_geo.get("country", "Unknown")

# FIXED: Extract ISP text smoothly without crashing
isp = "Unknown"
if "isp" in d_geo and isinstance(d_geo["isp"], str):
    isp = d_geo["isp"]
elif "connection" in d_geo and isinstance(d_geo["connection"], dict):
    isp = d_geo["connection"].get("isp", "Unknown")

# Consolidate Security Threat Vectors
vpn = bool(ipapi.get("proxy") or d_sec.get("vpn") or d_sec.get("proxy"))
hosting = bool(ipapi.get("hosting") or d_sec.get("hosting"))
mobile = bool(ipapi.get("mobile"))

# Dynamic Risk Score Engine
risk_score = (50 if vpn else 0) + (30 if hosting else 0)
verdict = "🔴 HIGH" if risk_score >= 70 else ("🟡 MEDIUM" if risk_score >= 30 else "🟢 LOW")

# Output Final Consolidated Report
print(f"\n🌍 Target IP    : {ip}")
print(f"🌎 Location     : {city}, {region}, {country}")
print(f"📡 Network ISP  : {isp}")

print("\n" + "-" * 15 + " SECURITY TRACKS " + "-" * 14)
print(f"🛡️  VPN / Proxy Active : {vpn}")
print(f"☁️  Data Center Host   : {hosting}")
print(f"📱 Mobile Data Carrier : {mobile}")
print(f"🚨 Risk Verdict        : {risk_score}/100 ({verdict})")
print("=" * 45)
