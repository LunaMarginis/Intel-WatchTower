import pandas as pd
import requests
from io import StringIO
import re
from datetime import datetime
import os
import requests

execution_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")

if not SLACK_WEBHOOK_URL:
    raise ValueError("SLACK_WEBHOOK_URL environment variable is not set")


# Step 1: Fetch data
url = "https://urlhaus.abuse.ch/downloads/csv_recent/"
resp = requests.get(url)
resp.raise_for_status()

# Step 2: Strip comment lines and read into DataFrame
#raw_lines = resp.text.splitlines()
#data_lines = [line for line in raw_lines if not line.startswith('#')]
#cleaned_data = "\n".join(data_lines)

# Step 3: Read as tab-separated values
#df = pd.read_csv(StringIO(cleaned_data), sep=',')  # This CSV is comma-separated after removing the comment lines

def sanitize_url(url):
    return re.sub(r"\.", "[.]", url).replace(":", "[:]")
    

df = pd.read_csv(StringIO(resp.text), comment='#', header=None, on_bad_lines='skip')

df = df.rename(columns={
    2: 'url',
    3: 'url_status',
    6: 'tags'
})


# Step 4: Group by 'tags' column
# First, filter out empty or NaN tags
#df = df[df['tags'].notna()]

df['url'] = df['url'].apply(sanitize_url)
df[['tags', 'url', 'url_status']].to_csv("urls.csv", index=False)


# Step 7: Save to CSV

summary = df.groupby('tags').size().reset_index(name='count')

readme_path = "README.md"
try:
    with open(readme_path, "r", encoding="utf-8") as f:
        readme = f.read()
except FileNotFoundError:
    readme = ""

# Build markdown summary table
summary = summary.sort_values(by='count', ascending=False).head(10)
md_lines = [
    "\n\n<!-- url_summary_start -->",
    "## 🔗 Top 10 URLs:\n",
    f"Automated URL Collections, grouped by Tags: Every day at 03:00 UTC. Last Updated: {execution_time}.\n",
    "| Tag | Count |",
    "|-----|-------|",
]

# Create summary table from 'summary' DataFrame
for _, row in summary.iterrows():
    md_lines.append(f"| {row['tags']} | {row['count']} |")

md_lines.append("<!-- url_summary_end -->\n")
summary_md = "\n".join(md_lines)

# Replace existing section or append at the end
section_start = "<!-- url_summary_start -->"
section_end = "<!-- url_summary_end -->"

if section_start in readme and section_end in readme:
    pre = readme.split(section_start)[0]
    post = readme.split(section_end)[1]
    updated_readme = pre + summary_md + post
else:
    updated_readme = readme + summary_md

# Write back to README.md
with open(readme_path, "w", encoding="utf-8") as f:
    f.write(updated_readme)
print("✅ urls.csv and README.md updated.")

# Read README.md content (or summary section)
with open("README.md", "r", encoding="utf-8") as f:
    readme_content = f.read()

section_start = "<!-- url_summary_start -->"
section_end = "<!-- url_summary_end -->"
if section_start in readme_content and section_end in readme_content:
    start_idx = readme_content.index(section_start)
    end_idx = readme_content.index(section_end) + len(section_end)
    summary_text = readme_content[start_idx:end_idx]
else:
    summary_text = readme_content  # fallback: send whole README

payload = {
    "text": f"Updated README Summary:\n{summary_text}"
}

response = requests.post(SLACK_WEBHOOK_URL, json=payload)

if response.status_code == 200:
    print("✅ Slack notification sent successfully.")
else:
    print(f"❌ Failed to send Slack notification: {response.status_code} - {response.text}")
