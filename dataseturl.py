import pandas as pd
import json
import argparse
from pathlib import Path


def convert_urls(input_file: str, output_file: str, limit: int = 10000):
    print(f"\n Reading: {input_file}")

    # Read CSV 
    df = pd.read_csv(input_file, header=None, names=["url", "type"])

    
    if str(df.iloc[0]['url']).lower() == 'url':
        df = df.iloc[1:].reset_index(drop=True)

    print(f" Total rows loaded: {len(df)}")
    print(f" Category breakdown:\n{df['type'].value_counts()}\n")

    # Filter out benign
    df_filtered = df[df['type'].str.lower() != 'benign'].copy()
    print(f" Rows after removing benign: {len(df_filtered)}")

    #  limit
    df_sampled = df_filtered.head(limit)
    print(f"  Rows after limit of {limit}: {len(df_sampled)}")

    # Category 
    category_map = {
        'phishing':    'Phishing',
        'malware':     'Malware',
        'defacement':  'Defacement',
    }

    # Build records
    records = []
    for _, row in df_sampled.iterrows():
        category = category_map.get(str(row['type']).lower(), str(row['type']).title())
        records.append({
            "type": "url",
            "value": str(row['url']).strip(),
            "Category": category
        })

    # Write JSON
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(records, f, indent=2, ensure_ascii=False)

    print(f"\n Done! {len(records)} URLs saved to: {output_file}")

    # Final breakdown
    categories = {}
    for r in records:
        categories[r['Category']] = categories.get(r['Category'], 0) + 1
    print(" Output breakdown:")
    for cat, count in sorted(categories.items()):
        print(f"   {cat}: {count}")

    
    print("\n Preview (first 3 records):")
    for r in records[:3]:
        print(json.dumps(r, ensure_ascii=False))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Convert Malicious URLs CSV to JSON")
    parser.add_argument("--input",  default="malicious_phish.csv", help="Input CSV file")
    parser.add_argument("--output", default="malicious_urls.json", help="Output JSON file")
    parser.add_argument("--limit",  type=int, default=10000,        help="Max URLs to include")
    parser.add_argument("--test",   action="store_true",            help="Test mode: only convert 10 URLs")
    args = parser.parse_args()

    if args.test:
        args.limit = 10
        args.output = "test_output.json"
        print(" TEST MODE — converting only 10 URLs → test_output.json")

    if not Path(args.input).exists():
        print(f"\n File not found: {args.input}")
        print("Make sure malicious_phish.csv is in the same folder as this script.")
        exit(1)

    convert_urls(args.input, args.output, args.limit)