import pandas as pd
import requests
from io import StringIO

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


df = pd.read_csv(StringIO(resp.text), comment='#', header=None, on_bad_lines='skip')

df = df.rename(columns={
    2: 'url',
    3: 'url_status',
    6: 'tags'
})


# Step 4: Group by 'tags' column
# First, filter out empty or NaN tags
#df = df[df['tags'].notna()]
df[['tags', 'url', 'url_status']].to_csv("urls.csv", index=False)


# Step 7: Save to CSV

summary = df.groupby(['tags', 'url']).size().reset_index(name='count')

print(summary)
readme_path = "README.md"
try:
    with open(readme_path, "r", encoding="utf-8") as f:
        readme = f.read()
except FileNotFoundError:
    readme = ""

# Build markdown summary table
md_lines = [
    "\n\n<!-- url_summary_start -->",
    "## 🔗 URL Summary\n",
    "| Tag | Count |   Url  |",
    "|-----|-------|---------",
]

# Create summary table from 'summary' DataFrame
for _, row in summary.iterrows():
    md_lines.append(f"| {row['tags']} | {row['count']} | {row['url']} |")

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
