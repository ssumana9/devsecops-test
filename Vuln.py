import pandas as pd
import json
import logging
import os
import argparse
from datetime import datetime
from flask import Flask, jsonify

# Try to import Matplotlib, handle missing module
try:
    import matplotlib.pyplot as plt
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    logging.warning("Matplotlib is not installed. Install it using 'pip install matplotlib' to enable chart generation.")
    MATPLOTLIB_AVAILABLE = False

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def read_csv(file_path):
    """Read and parse the CSV file."""
    try:
        df = pd.read_csv(file_path)
        df.columns = df.columns.str.strip()
        logging.info("CSV file loaded successfully.")
        return df
    except Exception as e:
        logging.error(f"Error reading CSV file: {e}")
        return None

def preprocess_data(df):
    """Clean and validate data."""
    column_mapping = {
        "Identifier": "CVE_Number",
        "CVSS": "CVSS_Score",
        "Severity": "Severity",
        "Package Name": "Affected_Package",
        "Fixed Version": "Fixed_Package_Version",
        "First detected date": "Discovery_Date",
        "Due date": "Audit_Due_Date",
        "Source": "Source",
        "Fixability": "Fixability"
    }
    df.rename(columns=column_mapping, inplace=True)
    df.dropna(subset=['CVSS_Score', 'Audit_Due_Date'], inplace=True)
    df.fillna({'Fixed_Package_Version': 'Not Available'}, inplace=True)
    df['Audit_Due_Date'] = pd.to_datetime(df['Audit_Due_Date'], format='%m/%d/%Y', errors='coerce')
    df['Discovery_Date'] = pd.to_datetime(df['Discovery_Date'], format='%m/%d/%Y', errors='coerce')
    df['CVSS_Score'] = pd.to_numeric(df['CVSS_Score'], errors='coerce')
    
    # Assign severity levels based on CVSS scores (Referenced from NIST guidelines)
    def map_severity(cvss):
        if 0.1 <= cvss <= 3.9:
            return 'Low'
        elif 4.0 <= cvss <= 6.9:
            return 'Medium'
        elif 7.0 <= cvss <= 8.9:
            return 'High'
        elif 9.0 <= cvss <= 10.0:
            return 'Critical'
        else:
            return 'Unknown'
    
    df['Severity'] = df['CVSS_Score'].apply(map_severity)
    df['Fix_Available'] = df['Fixability'].apply(lambda x: 'Available' if x == 'Fixable' else 'Not Available')
    return df

def calculate_priority(df, severity_weight, source_weight, fix_weight):
    """Calculate priority score with customizable weights."""
    severity_weights = {'Critical': severity_weight, 'High': severity_weight - 3, 'Medium': severity_weight - 5, 'Low': severity_weight - 7}
    
    # Source weightage reasoning:
    # AWS is weighted higher (5) because cloud infrastructure is critical to businesses, and security issues can affect entire environments.
    # GitHub is weighted lower (3) because issues generally impact source code and repositories, which may have mitigations like access control.
    source_weights = {'AWS': source_weight, 'GitHub': source_weight - 2}
    fix_weights = {'Not Available': fix_weight, 'Available': 1}
    today = datetime.today()
    df['Days_To_Audit'] = (df['Audit_Due_Date'] - today).dt.days
    df['Severity_Weight'] = df['Severity'].map(severity_weights).fillna(0)
    df['Source_Weight'] = df['Source'].map(source_weights).fillna(0)
    df['Fix_Weight'] = df['Fix_Available'].map(fix_weights).fillna(0)
    df['Priority_Score'] = (
        df['CVSS_Score'] * 4 + 
        (100 - df['Days_To_Audit']) * 0.25 + 
        df['Severity_Weight'] * 2 + 
        df['Source_Weight'] * 1 + 
        df['Fix_Weight'] * 0.5
    )
    df['Priority_Score'] = df['Priority_Score'].round(2)
    return df.sort_values(by='Priority_Score', ascending=False)

def generate_chart(df, output_chart):
    if not MATPLOTLIB_AVAILABLE:
        logging.warning("Skipping chart generation because Matplotlib is not installed.")
        return
    severity_order = ['Critical', 'High', 'Medium', 'Low']
    severity_counts = df['Severity'].value_counts().reindex(severity_order, fill_value=0)
    plt.figure(figsize=(8, 6))
    severity_counts.plot(kind='bar', color=['red', 'orange', 'yellow', 'green'])
    plt.xlabel("Severity")
    plt.ylabel("Number of Vulnerabilities")
    plt.title("Vulnerabilities by Severity")
    plt.xticks(rotation=45)
    plt.savefig(output_chart)
    plt.close()
    logging.info(f"Chart saved: {output_chart}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--severity_weight', type=int, default=10, help='Weight for severity levels')
    parser.add_argument('--source_weight', type=int, default=5, help='Weight for vulnerability source')
    parser.add_argument('--fix_weight', type=int, default=5, help='Weight for fix availability')
    args = parser.parse_args()
    
    base_path = "C:\\Users\\SaiSumanaSingaraju\\Desktop\\Sample Vul Project"
    csv_file = os.path.join(base_path, "vulnerabilities.csv")
    output_chart = os.path.join(base_path, "severity_chart.png")
    
    if not os.path.exists(csv_file):
        logging.error(f"File not found: {csv_file}")
    else:
        df = read_csv(csv_file)
        if df is not None:
            df = preprocess_data(df)
            df = calculate_priority(df, args.severity_weight, args.source_weight, args.fix_weight)
            generate_chart(df, output_chart)
        else:
            logging.error("Failed to process file.")

app = Flask(__name__)

if __name__ == "__main__":
    main()
    app.run(host='0.0.0.0', port=5000)
