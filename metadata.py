from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
import os
from datetime import datetime

def get_gps_info(exif_data):
    gps_info = {}
    if not exif_data:
        return None
    for tag, value in exif_data.items():
        decoded = TAGS.get(tag, tag)
        if decoded == "GPSInfo":
            for t in value:
                sub_tag = GPSTAGS.get(t, t)
                gps_info[sub_tag] = value[t]
    return gps_info

def convert_to_degrees(value):
    d = float(value[0])
    m = float(value[1])
    s = float(value[2])
    return d + (m / 60.0) + (s / 3600.0)

def extract_metadata(image_path):
    try:
        image = Image.open(image_path)
        exif_data = image._getexif()
        filename = os.path.basename(image_path)
        timestamp = datetime.now().strftime("%d.%m.%Y u %H:%M:%S")

        rows_html = ""
        gps_section = ""
        has_exif = bool(exif_data)

        if has_exif:
            for tag_id, value in exif_data.items():
                tag = TAGS.get(tag_id, tag_id)
                if tag != "GPSInfo" and not isinstance(value, bytes):
                    rows_html += f"""
                    <tr>
                        <td class="tag-name">{tag}</td>
                        <td class="tag-value">{value}</td>
                    </tr>"""

            gps_data = get_gps_info(exif_data)
            if gps_data and 'GPSLatitude' in gps_data and 'GPSLongitude' in gps_data:
                lat = convert_to_degrees(gps_data['GPSLatitude'])
                if gps_data.get('GPSLatitudeRef') != 'N':
                    lat = -lat
                lon = convert_to_degrees(gps_data['GPSLongitude'])
                if gps_data.get('GPSLongitudeRef') != 'E':
                    lon = -lon

                maps_url = f"https://www.google.com/maps?q={lat},{lon}"
                gps_section = f"""
                <div class="gps-card">
                    <div class="gps-header">
                        <span class="gps-icon">&#9679;</span>
                        <h2>Geolokacija Pronađena</h2>
                    </div>
                    <div class="gps-grid">
                        <div class="gps-item">
                            <span class="gps-label">Latitude</span>
                            <span class="gps-val">{lat:.6f}°</span>
                        </div>
                        <div class="gps-item">
                            <span class="gps-label">Longitude</span>
                            <span class="gps-val">{lon:.6f}°</span>
                        </div>
                    </div>
                    <a href="{maps_url}" target="_blank" class="maps-btn">
                        Otvori na Google Maps &#8599;
                    </a>
                </div>"""
        else:
            rows_html = """
            <tr>
                <td colspan="2" class="no-data">Slika nema EXIF metapodatke.</td>
            </tr>"""

        html = f"""<!DOCTYPE html>
<html lang="bs">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Metadata — {filename}</title>
    <link href="https://fonts.googleapis.com/css2?family=Syne:wght@400;600;700;800&family=DM+Mono:wght@300;400;500&display=swap" rel="stylesheet">
    <style>
        *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}

        :root {{
            --bg:       #0b0c10;
            --surface:  #13151c;
            --border:   #1e2130;
            --accent:   #4fffb0;
            --accent2:  #00b8ff;
            --text:     #e2e8f0;
            --muted:    #5a6380;
            --danger:   #ff4f7b;
        }}

        body {{
            background: var(--bg);
            color: var(--text);
            font-family: 'DM Mono', monospace;
            min-height: 100vh;
            padding: 2rem 1rem 4rem;
        }}

        /* Animated grid background */
        body::before {{
            content: '';
            position: fixed;
            inset: 0;
            background-image:
                linear-gradient(rgba(78,255,176,.03) 1px, transparent 1px),
                linear-gradient(90deg, rgba(78,255,176,.03) 1px, transparent 1px);
            background-size: 40px 40px;
            pointer-events: none;
            z-index: 0;
        }}

        .wrapper {{
            position: relative;
            z-index: 1;
            max-width: 860px;
            margin: 0 auto;
        }}

        /* ── HEADER ── */
        header {{
            display: flex;
            align-items: flex-start;
            justify-content: space-between;
            flex-wrap: wrap;
            gap: 1rem;
            margin-bottom: 2.5rem;
            padding-bottom: 1.5rem;
            border-bottom: 1px solid var(--border);
        }}

        .header-left h1 {{
            font-family: 'Syne', sans-serif;
            font-size: clamp(1.6rem, 4vw, 2.4rem);
            font-weight: 800;
            letter-spacing: -0.03em;
            line-height: 1.1;
            background: linear-gradient(135deg, var(--accent) 0%, var(--accent2) 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }}

        .header-left .subtitle {{
            margin-top: .35rem;
            font-size: .78rem;
            color: var(--muted);
            letter-spacing: .06em;
            text-transform: uppercase;
        }}

        .badge {{
            display: inline-flex;
            align-items: center;
            gap: .4rem;
            background: rgba(78,255,176,.08);
            border: 1px solid rgba(78,255,176,.2);
            color: var(--accent);
            font-size: .72rem;
            letter-spacing: .08em;
            text-transform: uppercase;
            padding: .3rem .75rem;
            border-radius: 2rem;
            white-space: nowrap;
        }}

        .badge::before {{
            content: '';
            display: inline-block;
            width: 6px; height: 6px;
            background: var(--accent);
            border-radius: 50%;
            animation: pulse 2s infinite;
        }}

        @keyframes pulse {{
            0%, 100% {{ opacity: 1; transform: scale(1); }}
            50%       {{ opacity: .4; transform: scale(.7); }}
        }}

        /* ── META INFO BAR ── */
        .meta-bar {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: .75rem;
            margin-bottom: 2rem;
        }}

        .meta-chip {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: .75rem 1rem;
            display: flex;
            flex-direction: column;
            gap: .2rem;
        }}

        .meta-chip .label {{
            font-size: .65rem;
            text-transform: uppercase;
            letter-spacing: .1em;
            color: var(--muted);
        }}

        .meta-chip .value {{
            font-size: .9rem;
            color: var(--text);
            font-weight: 500;
            word-break: break-all;
        }}

        /* ── TABLE ── */
        .table-wrap {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            overflow: hidden;
            margin-bottom: 1.5rem;
        }}

        .table-title {{
            display: flex;
            align-items: center;
            gap: .6rem;
            padding: 1rem 1.25rem;
            border-bottom: 1px solid var(--border);
            font-family: 'Syne', sans-serif;
            font-size: .85rem;
            font-weight: 700;
            letter-spacing: .05em;
            text-transform: uppercase;
            color: var(--muted);
        }}

        .table-title span {{
            display: inline-block;
            width: 8px; height: 8px;
            background: var(--accent2);
            border-radius: 50%;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
        }}

        tr {{
            border-bottom: 1px solid var(--border);
            transition: background .15s;
        }}

        tr:last-child {{ border-bottom: none; }}
        tr:hover {{ background: rgba(255,255,255,.02); }}

        td {{
            padding: .7rem 1.25rem;
            vertical-align: top;
            font-size: .82rem;
            line-height: 1.5;
        }}

        .tag-name {{
            color: var(--accent2);
            width: 38%;
            font-weight: 500;
            white-space: nowrap;
        }}

        .tag-value {{
            color: var(--text);
            opacity: .85;
            word-break: break-word;
        }}

        .no-data {{
            text-align: center;
            color: var(--muted);
            padding: 2.5rem;
            font-size: .9rem;
        }}

        /* ── GPS CARD ── */
        .gps-card {{
            background: linear-gradient(135deg,
                rgba(78,255,176,.06) 0%,
                rgba(0,184,255,.04) 100%);
            border: 1px solid rgba(78,255,176,.25);
            border-radius: 12px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
        }}

        .gps-header {{
            display: flex;
            align-items: center;
            gap: .6rem;
            margin-bottom: 1.25rem;
        }}

        .gps-icon {{
            color: var(--danger);
            font-size: 1rem;
            animation: pulse 1.4s infinite;
        }}

        .gps-header h2 {{
            font-family: 'Syne', sans-serif;
            font-size: 1rem;
            font-weight: 700;
            color: var(--accent);
            letter-spacing: .04em;
        }}

        .gps-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: .75rem;
            margin-bottom: 1.25rem;
        }}

        .gps-item {{
            background: rgba(0,0,0,.3);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: .75rem 1rem;
            display: flex;
            flex-direction: column;
            gap: .25rem;
        }}

        .gps-label {{
            font-size: .65rem;
            text-transform: uppercase;
            letter-spacing: .1em;
            color: var(--muted);
        }}

        .gps-val {{
            font-size: 1.05rem;
            font-weight: 500;
            color: var(--accent);
            font-family: 'Syne', sans-serif;
        }}

        .maps-btn {{
            display: inline-flex;
            align-items: center;
            gap: .4rem;
            background: var(--accent);
            color: #0b0c10;
            font-family: 'Syne', sans-serif;
            font-weight: 700;
            font-size: .8rem;
            letter-spacing: .06em;
            text-transform: uppercase;
            text-decoration: none;
            padding: .6rem 1.25rem;
            border-radius: 6px;
            transition: opacity .2s, transform .15s;
        }}

        .maps-btn:hover {{
            opacity: .85;
            transform: translateY(-1px);
        }}

        /* ── FOOTER ── */
        footer {{
            margin-top: 2.5rem;
            padding-top: 1.25rem;
            border-top: 1px solid var(--border);
            font-size: .72rem;
            color: var(--muted);
            text-align: center;
            letter-spacing: .05em;
        }}

        /* ── FADE-IN ANIMATION ── */
        .wrapper > * {{
            animation: fadeUp .5s ease both;
        }}
        .wrapper > *:nth-child(1) {{ animation-delay: 0s; }}
        .wrapper > *:nth-child(2) {{ animation-delay: .07s; }}
        .wrapper > *:nth-child(3) {{ animation-delay: .14s; }}
        .wrapper > *:nth-child(4) {{ animation-delay: .21s; }}
        .wrapper > *:nth-child(5) {{ animation-delay: .28s; }}

        @keyframes fadeUp {{
            from {{ opacity: 0; transform: translateY(14px); }}
            to   {{ opacity: 1; transform: translateY(0); }}
        }}
    </style>
</head>
<body>
<div class="wrapper">

    <header>
        <div class="header-left">
            <h1>EXIF Analiza</h1>
            <p class="subtitle">Ekstrakcija metapodataka slike</p>
        </div>
        <span class="badge">Izvještaj</span>
    </header>

    <div class="meta-bar">
        <div class="meta-chip">
            <span class="label">Fajl</span>
            <span class="value">{filename}</span>
        </div>
        <div class="meta-chip">
            <span class="label">Generirano</span>
            <span class="value">{timestamp}</span>
        </div>
        <div class="meta-chip">
            <span class="label">EXIF Status</span>
            <span class="value" style="color: {'#4fffb0' if has_exif else '#ff4f7b'}">
                {'Pronađeno' if has_exif else 'Nije pronađeno'}
            </span>
        </div>
    </div>

    {gps_section}

    <div class="table-wrap">
        <div class="table-title">
            <span></span> EXIF Metapodaci
        </div>
        <table>
            {rows_html}
        </table>
    </div>

    <footer>
        Metadata Extractor &nbsp;·&nbsp; {timestamp}
    </footer>

</div>
</body>
</html>"""

        output_path = "metadata_report.html"
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)

        print(f"✓ Izvještaj sačuvan: {output_path}")

    except Exception as e:
        print(f"Greška: {e}")

image_path = input("Unesi putanju do slike: ")
extract_metadata(image_path)