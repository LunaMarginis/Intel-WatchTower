import pandas as pd
from io import StringIO

from abusech import threatfox_full_csv

# Download full ThreatFox export (authenticated, rate-limited, cached) and keep MD5 IOCs
text = threatfox_full_csv()
lines = [l[2:] if l.startswith('# "first_seen_utc"') else l for l in text.splitlines() if not l.startswith('#') or l.startswith('# "first_seen_utc"')]
df = pd.read_csv(StringIO("\n".join(lines)), skipinitialspace=True, dtype=str)
df = df[df['ioc_type'] == 'md5_hash']

# Treat the literal "None" / empty values as missing so the bfill below works
df = df.replace({'None': pd.NA, '': pd.NA})

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
    f.write("This table shows top 10 malware names with their unique IOC hashes and counts.\n\n")
    f.write(markdown_content)

print("✅ README.md generated with IOC summary.")
print("mhash.csv and README.md updated.")
