"""Shared hosting, code, storage and tunnelling platforms that attackers abuse.

A malware URL on raw.githubusercontent.com tells you the attacker has a GitHub account, not where their infrastructure is, and nobody can block GitHub. In the
"busiest hosts" lists these would crowd out the hosts that ARE worth checking one by one (dedicated domains and bare IP addresses), so they are counted
separately as "abused platforms": that is intelligence too (which services are being used right now), just a different kind.

A host belongs to a platform when it IS the platform domain or a subdomain of it (a.blob.core.windows.net -> blob.core.windows.net). Keep the list to services
many unrelated customers share; a name that only looks familiar must not be added, or a real attacker domain would disappear from the lists."""
from __future__ import annotations

# platform domain -> label shown in reports
PLATFORMS: dict[str, str] = {
    # code and file hosting
    "github.com": "GitHub", "githubusercontent.com": "GitHub", "github.io": "GitHub Pages", "gitlab.com": "GitLab", "bitbucket.org": "Bitbucket", "sourceforge.net": "SourceForge",
    "codeberg.org": "Codeberg", "gitee.com": "Gitee", "pastebin.com": "Pastebin", "paste.ee": "Paste.ee", "ghostbin.org": "Ghostbin", "hastebin.com": "Hastebin",
    # cloud storage and file sharing
    "dropbox.com": "Dropbox", "dropboxusercontent.com": "Dropbox", "drive.google.com": "Google Drive", "docs.google.com": "Google Docs", "storage.googleapis.com": "Google Cloud Storage",
    "googleusercontent.com": "Google", "onedrive.live.com": "OneDrive", "1drv.ms": "OneDrive", "sharepoint.com": "SharePoint", "mega.nz": "MEGA", "mega.io": "MEGA",
    "mediafire.com": "MediaFire", "wetransfer.com": "WeTransfer", "we.tl": "WeTransfer", "transfer.sh": "transfer.sh", "sendspace.com": "SendSpace", "4shared.com": "4shared",
    "box.com": "Box", "archive.org": "Internet Archive", "ipfs.io": "IPFS gateway", "dweb.link": "IPFS gateway", "cloudflare-ipfs.com": "IPFS gateway",
    "blob.core.windows.net": "Azure Blob Storage", "azurewebsites.net": "Azure App Service", "amazonaws.com": "AWS", "cloudfront.net": "CloudFront", "digitaloceanspaces.com": "DigitalOcean Spaces",
    "backblazeb2.com": "Backblaze B2", "r2.dev": "Cloudflare R2",
    # chat and messaging
    "discord.com": "Discord", "discordapp.com": "Discord", "discordapp.net": "Discord", "discord.gg": "Discord", "telegram.org": "Telegram", "t.me": "Telegram", "telegra.ph": "Telegram",
    "slack.com": "Slack", "slack-files.com": "Slack",
    # app and page hosting, tunnels
    "vercel.app": "Vercel", "netlify.app": "Netlify", "herokuapp.com": "Heroku", "firebaseapp.com": "Firebase", "web.app": "Firebase", "pages.dev": "Cloudflare Pages", "workers.dev": "Cloudflare Workers",
    "trycloudflare.com": "Cloudflare Tunnel", "ngrok.io": "ngrok", "ngrok-free.app": "ngrok", "ngrok.app": "ngrok", "loca.lt": "localtunnel", "serveo.net": "serveo", "glitch.me": "Glitch",
    "repl.co": "Replit", "replit.app": "Replit", "onrender.com": "Render", "fly.dev": "Fly.io", "railway.app": "Railway", "surge.sh": "Surge", "000webhostapp.com": "000webhost",
    "weebly.com": "Weebly", "wixsite.com": "Wix", "blogspot.com": "Blogger", "wordpress.com": "WordPress.com", "notion.site": "Notion", "canva.com": "Canva", "typedream.app": "Typedream",
    # delivery networks and link shorteners
    "jsdelivr.net": "jsDelivr", "unpkg.com": "unpkg", "bit.ly": "Bitly", "tinyurl.com": "TinyURL", "cutt.ly": "Cuttly", "rebrand.ly": "Rebrandly", "is.gd": "is.gd", "t.co": "X (Twitter)",
}


def platform_of(host: str) -> str | None:
    """The platform label for a host, or None when it is not on a known platform. Case-insensitive; ignores a port and a trailing dot."""
    h = (host or "").strip().lower().rstrip(".").split(":")[0]
    if not h or h.replace(".", "").isdigit():   # bare IPv4 addresses are never platforms
        return None
    parts = h.split(".")
    for i in range(len(parts) - 1):
        label = PLATFORMS.get(".".join(parts[i:]))
        if label:
            return label
    return None
