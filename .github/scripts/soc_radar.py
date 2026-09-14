import json
import math
import os
import re
import urllib.request

USERNAME = "duaa-adnan"
API_URL = f"https://api.github.com/users/{USERNAME}/repos?per_page=100"

CATEGORIES = {
    "SIEM": ["wazuh", "siem", "detection", "decoder"],
    "DFIR": ["forensic", "dfir", "autopsy", "registry", "m57", "mantooth",
             "memory", "disk", "artifact", "timeline"],
    "MALWARE": ["malware", "trojan", "zeus", "breach", "ioc"],
    "NETWORK": ["suricata", "ids", "pfsense", "firewall", "squid", "clamav"],
    "AUTOMATION": ["n8n", "gemini", "automation", "pipeline"],
}

BG = "#0a0e14"
CARD = "#0d1117"
BORDER = "#232b36"
TEXT = "#c9d1d9"
DIM = "#6b7280"
GREEN = "#4ADE80"
FONT = "Consolas, 'Courier New', monospace"


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "soc-radar-bot"})
    with urllib.request.urlopen(req, timeout=15) as response:
        return response.read()


def categorize(repo):
    text = (repo.get("name", "") + " " + (repo.get("description") or "")).lower()
    hits = set()
    for cat, keywords in CATEGORIES.items():
        if any(k in text for k in keywords):
            hits.add(cat)
    return hits


def build_radar_svg(counts, max_val):
    cx, cy, r = 230, 200, 120
    n = len(counts)
    angle_step = 2 * math.pi / n
    start_angle = -math.pi / 2

    def point(i, value_ratio):
        angle = start_angle + i * angle_step
        return (cx + r * value_ratio * math.cos(angle),
                cy + r * value_ratio * math.sin(angle))

    # grid rings
    rings = ""
    for frac in [0.25, 0.5, 0.75, 1.0]:
        pts = " ".join(f"{point(i, frac)[0]:.1f},{point(i, frac)[1]:.1f}" for i in range(n))
        rings += f'<polygon points="{pts}" fill="none" stroke="{BORDER}" stroke-width="1"/>\n  '

    # axis lines + labels
    axes = ""
    labels = ""
    for i, cat in enumerate(counts.keys()):
        x, y = point(i, 1.0)
        axes += f'<line x1="{cx}" y1="{cy}" x2="{x:.1f}" y2="{y:.1f}" stroke="{BORDER}" stroke-width="1"/>\n  '
        lx, ly = point(i, 1.18)
        anchor = "middle"
        if lx < cx - 10:
            anchor = "end"
        elif lx > cx + 10:
            anchor = "start"
        labels += f'<text x="{lx:.1f}" y="{ly:.1f}" font-family="{FONT}" font-size="12" fill="{TEXT}" text-anchor="{anchor}">{cat}</text>\n  '

    # data polygon
    data_pts = []
    for i, val in enumerate(counts.values()):
        ratio = 0.08 if val == 0 else min(val / max_val, 1.0)
        data_pts.append(point(i, ratio))
    poly_str = " ".join(f"{x:.1f},{y:.1f}" for x, y in data_pts)

    blips = ""
    for i, (cat, val) in enumerate(counts.items()):
        x, y = data_pts[i]
        blips += f'<circle cx="{x:.1f}" cy="{y:.1f}" r="4" fill="{GREEN}"/>\n  '
        vx, vy = point(i, (0.08 if val == 0 else min(val / max_val, 1.0)) + 0.09)
        blips += f'<text x="{vx:.1f}" y="{vy:.1f}" font-family="{FONT}" font-size="11" fill="{GREEN}" text-anchor="middle">{val}</text>\n  '

    # rotating sweep wedge
    sweep = f'''
  <defs>
    <radialGradient id="sweepGrad" cx="0" cy="0" r="1" gradientUnits="userSpaceOnUse"
      gradientTransform="translate({cx} {cy}) rotate(0) scale({r})">
      <stop offset="0%" stop-color="{GREEN}" stop-opacity="0.35"/>
      <stop offset="100%" stop-color="{GREEN}" stop-opacity="0"/>
    </radialGradient>
    <clipPath id="radarClip">
      <circle cx="{cx}" cy="{cy}" r="{r}"/>
    </clipPath>
  </defs>
  <g clip-path="url(#radarClip)">
    <path d="M {cx} {cy} L {cx} {cy - r} A {r} {r} 0 0 1 {cx + r * math.sin(math.radians(35)):.1f} {cy - r * math.cos(math.radians(35)):.1f} Z"
          fill="url(#sweepGrad)">
      <animateTransform attributeName="transform" type="rotate"
        from="0 {cx} {cy}" to="360 {cx} {cy}" dur="4s" repeatCount="indefinite"/>
    </path>
  </g>'''

    total_h = 400
    total_w = 460
    svg = f'''<svg width="{total_w}" height="{total_h}" viewBox="0 0 {total_w} {total_h}" xmlns="http://www.w3.org/2000/svg">
  <rect width="{total_w}" height="{total_h}" rx="10" fill="{CARD}" stroke="{BORDER}" stroke-width="1.5"/>
  <circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="{BORDER}" stroke-width="1"/>
  {rings}
  {axes}
  {sweep}
  <polygon points="{poly_str}" fill="{GREEN}" fill-opacity="0.18" stroke="{GREEN}" stroke-width="2"/>
  {blips}
  {labels}
  <text x="230" y="30" font-family="{FONT}" font-size="13" fill="{DIM}" text-anchor="middle">SOC THREAT RADAR // COVERAGE BY DOMAIN</text>
</svg>'''
    return svg


def main():
    repos = json.loads(fetch(API_URL))
    counts = {cat: 0 for cat in CATEGORIES}

    for repo in repos:
        if repo.get("name", "").lower() == USERNAME.lower() or repo.get("fork"):
            continue
        for cat in categorize(repo):
            counts[cat] += 1

    max_val = max(max(counts.values()), 1)
    svg = build_radar_svg(counts, max_val)

    os.makedirs("badges", exist_ok=True)
    with open("badges/soc-radar.svg", "w") as f:
        f.write(svg)

    print("Category counts:", counts)


if __name__ == "__main__":
    main()
