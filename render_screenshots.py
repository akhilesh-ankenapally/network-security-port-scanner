"""
Render high-resolution UI preview screenshots for the screenshots/ folder using Pillow.
Captures the exact visual layout of the dark-mode cyber interface.
"""

import os
from PIL import Image, ImageDraw, ImageFont

os.makedirs("screenshots", exist_ok=True)

# Colors matching style.css
BG_MAIN = (11, 15, 25)
BG_CARD = (17, 24, 39)
BG_INPUT = (14, 20, 36)
BORDER = (31, 41, 61)
BORDER_HL = (46, 61, 91)
TEXT_WHITE = (243, 244, 246)
TEXT_SEC = (148, 163, 184)
TEXT_MUTED = (100, 116, 139)
ACCENT_CYAN = (6, 182, 212)
ACCENT_EMERALD = (16, 185, 129)
ACCENT_ROSE = (244, 63, 94)
EMERALD_BG = (16, 185, 129, 45)
CLOSED_BG = (100, 116, 139, 35)

WIDTH, HEIGHT = 1200, 780


def create_base():
    img = Image.new("RGB", (WIDTH, HEIGHT), BG_MAIN)
    draw = ImageDraw.Draw(img)

    # Header Card
    draw.rounded_rectangle([40, 24, 1160, 94], radius=10, fill=BG_CARD, outline=BORDER)
    # Header Icon Box
    draw.rounded_rectangle([56, 36, 100, 80], radius=8, fill=(6, 182, 212, 40), outline=ACCENT_CYAN)
    draw.text((70, 48), "#", fill=ACCENT_CYAN)

    # Header Titles
    draw.text((115, 40), "NETWORK SECURITY PORT SCANNER", fill=TEXT_WHITE)
    draw.text((115, 62), "Academic Prototype  *  Multithreaded TCP Socket Engine (RFC 793)", fill=TEXT_SEC)

    # Header Badges
    draw.rounded_rectangle([920, 46, 1030, 74], radius=14, fill=(6, 182, 212, 25), outline=ACCENT_CYAN)
    draw.text((935, 52), "TCP SYN-ACK", fill=ACCENT_CYAN)

    draw.rounded_rectangle([1045, 46, 1140, 74], radius=14, fill=(16, 185, 129, 30), outline=ACCENT_EMERALD)
    draw.text((1060, 52), "Engine Ready", fill=ACCENT_EMERALD)

    # Left Card (Scan Parameters)
    draw.rounded_rectangle([40, 115, 430, 700], radius=12, fill=BG_CARD, outline=BORDER)
    draw.text((60, 135), "[*] Scan Parameters", fill=TEXT_WHITE)

    # Target IP field
    draw.text((60, 175), "TARGET IP / HOSTNAME", fill=TEXT_SEC)
    draw.rounded_rectangle([60, 198, 410, 238], radius=6, fill=BG_INPUT, outline=ACCENT_CYAN)
    draw.text((75, 210), "127.0.0.1", fill=TEXT_WHITE)

    # Preset Target Chips
    draw.text((60, 248), "Quick:", fill=TEXT_MUTED)
    draw.rounded_rectangle([105, 245, 220, 268], radius=4, fill=BG_INPUT, outline=BORDER)
    draw.text((115, 250), "Localhost (127.0.0.1)", fill=TEXT_SEC)
    draw.rounded_rectangle([230, 245, 335, 268], radius=4, fill=BG_INPUT, outline=BORDER)
    draw.text((238, 250), "scanme.nmap.org", fill=TEXT_SEC)

    # Mode tabs
    draw.rounded_rectangle([60, 285, 410, 320], radius=6, fill=BG_INPUT, outline=BORDER)
    draw.rounded_rectangle([63, 288, 175, 317], radius=4, fill=BORDER, outline=BORDER)
    draw.text((80, 296), "Port Range", fill=ACCENT_CYAN)
    draw.text((195, 296), "Profiles", fill=TEXT_MUTED)
    draw.text((310, 296), "Custom", fill=TEXT_MUTED)

    # Port Range Inputs
    draw.text((60, 338), "START PORT", fill=TEXT_SEC)
    draw.rounded_rectangle([60, 360, 225, 400], radius=6, fill=BG_INPUT, outline=BORDER)
    draw.text((75, 372), "20", fill=TEXT_WHITE)

    draw.text((245, 338), "END PORT", fill=TEXT_SEC)
    draw.rounded_rectangle([245, 360, 410, 400], radius=6, fill=BG_INPUT, outline=BORDER)
    draw.text((260, 372), "100", fill=TEXT_WHITE)

    # Range Presets
    draw.rounded_rectangle([60, 415, 175, 438], radius=12, fill=BG_INPUT, outline=BORDER)
    draw.text((70, 421), "Common (20-100)", fill=ACCENT_CYAN)
    draw.rounded_rectangle([185, 415, 290, 438], radius=12, fill=BG_INPUT, outline=BORDER)
    draw.text((195, 421), "Privileged (1-1024)", fill=TEXT_MUTED)

    # Timeout Slider
    draw.text((60, 465), "SOCKET TIMEOUT: 0.4s", fill=TEXT_SEC)
    draw.rounded_rectangle([60, 490, 410, 496], radius=3, fill=BORDER)
    draw.rounded_rectangle([60, 490, 180, 496], radius=3, fill=ACCENT_CYAN)
    draw.ellipse([175, 485, 187, 501], fill=ACCENT_CYAN)

    # Action Buttons
    draw.rounded_rectangle([60, 535, 320, 580], radius=6, fill=(2, 132, 199), outline=ACCENT_CYAN)
    draw.text((95, 548), "> Execute Port Scan", fill=TEXT_WHITE)

    draw.rounded_rectangle([335, 535, 410, 580], radius=6, fill=BORDER)
    draw.text((355, 548), "Reset", fill=TEXT_SEC)

    # Info footer in left card
    draw.text((60, 620), "Protocols: TCP Connect", fill=TEXT_MUTED)
    draw.text((60, 640), "Concurrency: ThreadPoolExecutor (60 workers)", fill=TEXT_MUTED)
    draw.text((60, 660), "Safe academic environment prototype", fill=TEXT_MUTED)

    return img, draw


# Screenshot 1: Active Scan Results
def generate_scan_results_screenshot():
    img, draw = create_base()

    # Summary Metrics Cards
    metrics = [
        ("TARGET IP", "127.0.0.1", ACCENT_CYAN),
        ("PORTS SCANNED", "81", TEXT_WHITE),
        ("OPEN PORTS", "3", ACCENT_EMERALD),
        ("CLOSED PORTS", "78", TEXT_SEC),
        ("SCAN TIME", "0.34s", TEXT_WHITE),
    ]

    card_x = 450
    for label, val, color in metrics:
        draw.rounded_rectangle([card_x, 115, card_x + 130, 180], radius=8, fill=BG_CARD, outline=BORDER)
        draw.text((card_x + 12, 125), label, fill=TEXT_MUTED)
        draw.text((card_x + 12, 145), val, fill=color)
        card_x += 142

    # Results Table Card
    draw.rounded_rectangle([450, 198, 1160, 700], radius=12, fill=BG_CARD, outline=BORDER)

    # Table Header & Filters
    draw.text((470, 215), "PORT SCAN RESULTS (81 entries)", fill=TEXT_WHITE)

    # Filter toggles
    draw.rounded_rectangle([880, 210, 950, 235], radius=4, fill=BORDER)
    draw.text((890, 217), "All Ports", fill=TEXT_WHITE)

    draw.rounded_rectangle([960, 210, 1050, 235], radius=4, fill=BG_INPUT, outline=ACCENT_EMERALD)
    draw.text((970, 217), "Open Only (3)", fill=ACCENT_EMERALD)

    # Search box
    draw.rounded_rectangle([1060, 210, 1140, 235], radius=4, fill=BG_INPUT, outline=BORDER)
    draw.text((1070, 217), "Filter...", fill=TEXT_MUTED)

    # Table Columns
    draw.rectangle([450, 250, 1160, 280], fill=(13, 19, 32))
    draw.text((475, 260), "PORT", fill=TEXT_MUTED)
    draw.text((545, 260), "SERVICE NAME", fill=TEXT_MUTED)
    draw.text((840, 260), "STATUS", fill=TEXT_MUTED)
    draw.text((945, 260), "LATENCY", fill=TEXT_MUTED)
    draw.text((1035, 260), "DETAILS", fill=TEXT_MUTED)

    # Rows
    rows = [
        (21, "FTP (File Transfer Protocol)", "CLOSED", "0.45 ms", "Connection refused"),
        (22, "SSH (Secure Shell)", "CLOSED", "0.51 ms", "Connection refused"),
        (23, "Telnet (Unencrypted text)", "CLOSED", "0.48 ms", "Connection refused"),
        (25, "SMTP (Simple Mail Transfer)", "CLOSED", "0.42 ms", "Connection refused"),
        (53, "DNS (Domain Name System)", "CLOSED", "0.39 ms", "Connection refused"),
        (80, "HTTP (Hypertext Transfer)", "OPEN", "0.82 ms", "HTTP/1.1 200 OK"),
        (135, "MS-RPC (Microsoft RPC Endpoint)", "OPEN", "0.95 ms", "Active RPC Endpoint"),
        (443, "HTTPS (HTTP Secure / TLS)", "CLOSED", "0.41 ms", "Connection refused"),
        (445, "SMB (Server Message Block)", "OPEN", "0.78 ms", "Active Windows Share"),
    ]

    y = 295
    for port, service, status, latency, banner in rows:
        draw.line([465, y - 8, 1145, y - 8], fill=(26, 35, 52), width=1)
        draw.text((475, y), str(port), fill=TEXT_WHITE)
        draw.text((545, y), service, fill=TEXT_WHITE)

        if status == "OPEN":
            draw.rounded_rectangle([835, y - 2, 905, y + 18], radius=10, fill=(16, 185, 129, 35), outline=ACCENT_EMERALD)
            draw.text((850, y + 2), "OPEN", fill=ACCENT_EMERALD)
        else:
            draw.rounded_rectangle([835, y - 2, 915, y + 18], radius=10, fill=(100, 116, 139, 25), outline=BORDER)
            draw.text((848, y + 2), "CLOSED", fill=TEXT_MUTED)

        draw.text((945, y), latency, fill=TEXT_SEC)
        draw.text((1035, y), banner, fill=TEXT_MUTED)
        y += 40

    img.save("screenshots/01_active_scan_results.png")
    print("Saved screenshots/01_active_scan_results.png")


# Screenshot 2: Error Handling & Validation
def generate_error_screenshot():
    img, draw = create_base()

    # Error Alert Banner
    draw.rounded_rectangle([450, 115, 1160, 175], radius=8, fill=(244, 63, 94, 25), outline=ACCENT_ROSE)
    draw.text((470, 135), "(!)", fill=ACCENT_ROSE)
    draw.text((495, 135), "DNS resolution failed for 'invalid.target.xyz999'. Hostname or IP is invalid or unreachable.", fill=(253, 164, 175))

    # Empty State Table
    draw.rounded_rectangle([450, 195, 1160, 700], radius=12, fill=BG_CARD, outline=BORDER)
    draw.text((470, 215), "PORT SCAN RESULTS", fill=TEXT_WHITE)

    draw.text((700, 420), "(O) Ready for Port Scan", fill=TEXT_MUTED)
    draw.text((620, 445), "Please correct the target address and click 'Execute Port Scan' to begin.", fill=TEXT_MUTED)

    img.save("screenshots/02_error_handling.png")
    print("Saved screenshots/02_error_handling.png")


if __name__ == "__main__":
    generate_scan_results_screenshot()
    generate_error_screenshot()
