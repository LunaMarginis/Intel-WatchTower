import pandas as pd
import requests
from io import StringIO
from datetime import datetime

execution_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

# Download CSV
url = "https://threatfox.abuse.ch/export/csv/md5/recent/"
response = requests.get(url)
response.raise_for_status()

# Convert to DataFrame
df = pd.read_csv(StringIO(response.text), comment='#', header=None, on_bad_lines='skip')

df = df.rename(columns={
    2: 'ioc_value',          # Column C
    5: 'fk_malware',         # Column F
    6: 'malware_alias',      # Column G
    7: 'malware_printable'   # Column H
})


grouped = df.groupby(['ioc_value', 'fk_malware', 'malware_alias', 'malware_printable']).size().reset_index(name='count')

# Save to CSV
grouped.to_csv("mhash.csv", index=False)


summary_df = grouped.copy()

# Collapse malware fields into a single 'Malware Name' using backfill (left to right)
summary_df['Malware Name'] = summary_df[['fk_malware', 'malware_alias', 'malware_printable']].bfill(axis=1).iloc[:, 0]

unique_iocs = summary_df[['ioc_value', 'Malware Name']].drop_duplicates()


# Count unique ioc_value per Malware Name
malware_counts = unique_iocs.groupby('Malware Name')['ioc_value'].nunique().reset_index(name='Count')


# Sort by count descending and take top 10
top_summary = malware_counts.sort_values(by='Count', ascending=False).head(10)

# Rename for display consistency
top_summary = top_summary.rename(columns={'Malware Name': 'Malware Name', 'Count': 'Count'})


# Merge to get the ioc_values per malware name
top_malware_names = top_summary['Malware Name'].tolist()

# Filter original summary for only top malware names
filtered_df = summary_df[summary_df['Malware Name'].isin(top_malware_names)]

# Group ioc_values as list per malware
grouped_iocs = filtered_df.groupby('Malware Name')['ioc_value'].apply(list).reset_index()

# Merge with count info
final_md_df = pd.merge(top_summary, grouped_iocs, on='Malware Name')

# Build markdown table string
md_lines = [
    "| Malware Name | ioc_value (Hashes) | Count |",
    "|--------------|--------------------|-------|"
]

for _, row in final_md_df.iterrows():
    malware = row['Malware Name']
    count = row['Count']
    # Join ioc_values with <br> for multiline in markdown cells (GitHub supports it)
    iocs_md = "<br>".join(row['ioc_value'])
    md_lines.append(f"| {malware} | {iocs_md} | {count} |")

markdown_content = "\n".join(md_lines)

# Write to README.md (overwrites or create)
with open("README.md", "w", encoding="utf-8") as f:
    f.write("# IOC Summary\n\n")
    f.write(f"Automated Hash Collections: Every day at 02:00 UTC. Last Updated: {execution_time}\n\n")
    f.write("This table shows top 10 malware names with their unique hashes and counts.\n\n")
    f.write(markdown_content)

print("mhash.csv and README.md updated.")
