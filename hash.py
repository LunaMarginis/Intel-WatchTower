import pandas as pd
import requests
from io import StringIO

# Download CSV
url = "https://threatfox.abuse.ch/export/csv/md5/recent/"
response = requests.get(url)
response.raise_for_status()

# Convert to DataFrame
df = pd.read_csv(StringIO(response.text), comment='#')

# Group and count
grouped = df.groupby(['ioc_value', 'fk_malware', 'malware_alias', 'malware_printable']).size().reset_index(name='count')

# Save to CSV
grouped.to_csv("mhash.csv", index=False)

# Prepare Markdown summary
summary_df = grouped.rename(columns={
    'ioc_value': 'HashValue',
    'fk_malware': 'Malware Name',
    'malware_alias': 'Malware Name',
    'malware_printable': 'Malware Name',
    'count': 'Count'
})

# Drop duplicates after collapsing columns to a single Malware Name
summary_df['Malware Name'] = summary_df[['fk_malware', 'malware_alias', 'malware_printable']].bfill(axis=1).iloc[:, 0]
summary_df = summary_df[['HashValue', 'Malware Name', 'Count']]

# Keep top 10 for summary
top_summary = summary_df.sort_values(by='Count', ascending=False).head(10)

# Format as Markdown
table_md = "| HashValue | Malware Name | Count |\n|-----------|--------------|-------|\n"
table_md += "\n".join(f"| {row.HashValue} | {row['Malware Name']} | {row.Count} |" for _, row in top_summary.iterrows())

# Update README.md
readme_path = "README.md"
section_start = "<!-- ioc_summary_start -->"
section_end = "<!-- ioc_summary_end -->"
new_section = f"{section_start}\n\n### 🔍 IOC Summary (Top 10)\n\n{table_md}\n\n{section_end}"

# Read existing README or create
try:
    with open(readme_path, "r") as f:
        readme = f.read()
except FileNotFoundError:
    readme = ""

# Replace or insert section
if section_start in readme and section_end in readme:
    readme = readme.split(section_start)[0] + new_section + readme.split(section_end)[1]
else:
    readme += f"\n\n{new_section}"

# Save updated README
with open(readme_path, "w") as f:
    f.write(readme)

print("mhash.csv and README.md updated.")
