import shutil
import subprocess
import os
import hashlib
import csv
import requests
import json
import scapy.all as scapy
import pandas as pd
import ipaddress
import glob
from datetime import datetime
from jinja2 import Template
import sys

current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

from HYBRID_CSV import hybrid_csv
from VT_CSV import vt_csv
from radare_csv import iIj_rdare, isj_rdare, iSj_rdare, izj_rdare, irj_rdare


hybrid_key = os.environ.get("HYBRID_API_KEY")
vt_key = os.environ.get("VT_API_KEY")
findip_key = os.environ.get("FINDIP_API_KEY")
abuseipdb_key = os.environ.get("ABUSEIPDB_API_KEY")


# Extract all files from the PCAP file
def extract_files(pcap_file):
    exe_path = "/content/dependency/networkminer-cli/CLI/bin/Debug/net48/NetworkMinerCLI.exe"
    subprocess.run(f"mono {exe_path} -r {pcap_file}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    source_folder = "dependency/networkminer-cli/CLI/bin/Debug/net48/AssembledFiles"
    destination_folder = os.path.join(work_dir_name, "files/captured_files")
    os.makedirs(destination_folder, exist_ok=True)

    if os.path.exists(source_folder):
        for file in os.listdir(source_folder):
            shutil.move(os.path.join(source_folder, file), os.path.join(destination_folder, file))
    shutil.rmtree(source_folder)


# Scan all files using ClamAV to detect malware
def detect_malware():
    # Create target directory
    malware_folder = os.path.join(work_dir_name, "files/malicious_files")
    os.makedirs(malware_folder, exist_ok=True)

    # Run clamscan and copy found files
    captured_files = os.path.join(work_dir_name, "files/captured_files")
    result = subprocess.run(['clamscan', '-r', captured_files], stdout=subprocess.PIPE, text=True)

    for line in result.stdout.splitlines():
        if 'FOUND' in line:
            file_path = line.split(':')[0].strip()
            if os.path.exists(file_path):
                shutil.copy(file_path, malware_folder)


def calculate_hashes():
    malware_folder = os.path.join(work_dir_name, "files/malicious_files")
    output_csv = os.path.join(malware_folder, "malicious_files_details.csv")

    def sha256(file_path):
        with open(file_path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()

    with open(output_csv, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["file_name", "sha256", "extension", "size (bytes)"])
        for file_name in os.listdir(malware_folder):
            if file_name == "malicious_files_details.csv":
                continue  # Skip this file
            file_path = os.path.join(malware_folder, file_name)
            if os.path.isfile(file_path):
                writer.writerow(
                    [file_name, sha256(file_path), os.path.splitext(file_name)[1], os.path.getsize(file_path)])


def hybrid_intel():
    def get_hybrid_analysis(hash_value, file_name):
        response = requests.post(
            'https://www.hybrid-analysis.com/api/v2/search/hash',
            headers={'accept': 'application/json',
                     'api-key': hybrid_key},
            data={'hash': hash_value}
        )
        if response.status_code == 200:
            output_dir = os.path.join(work_dir_name, "files/threat_intelligence_jsons")
            os.makedirs(output_dir, exist_ok=True)  # Ensure the directory exists
            file_path = os.path.join(output_dir, f'[HYBRID][{file_name}][{hash_value}].json')
            with open(file_path, 'w') as f:
                json.dump(response.json(), f, indent=4)

    def process_csv_and_fetch_data(csv_path):
        with open(csv_path, 'r') as csv_file:
            reader = csv.DictReader(csv_file)
            for row in reader:
                file_name = row['file_name']
                sha256 = row['sha256']
                get_hybrid_analysis(sha256, file_name)

    malicious_files_details = os.path.join(work_dir_name, "files/malicious_files/malicious_files_details.csv")
    process_csv_and_fetch_data(malicious_files_details)


def vt_intel():
    def get_vt_analysis(hash_value, file_name):
        url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
        headers = {
            "accept": "application/json",
            "x-apikey": vt_key
        }

        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            output_dir = os.path.join(work_dir_name, "files/threat_intelligence_jsons")
            os.makedirs(output_dir, exist_ok=True)  # Ensure the directory exists
            file_path = os.path.join(output_dir, f'[VT][{file_name}][{hash_value}].json')
            with open(file_path, 'w') as f:
                json.dump(response.json(), f, indent=4)

    def process_csv_and_fetch_data(csv_path):
        with open(csv_path, 'r') as csv_file:
            reader = csv.DictReader(csv_file)
            for row in reader:
                file_name = row['file_name']
                sha256 = row['sha256']
                get_vt_analysis(sha256, file_name)

    malicious_files_details = os.path.join(work_dir_name, "files/malicious_files/malicious_files_details.csv")
    process_csv_and_fetch_data(malicious_files_details)


def rdare2_analysis():
    malicious_files_dir = os.path.join(work_dir_name, "files/malicious_files")
    output_dir = os.path.join(work_dir_name, "files/radare2_txts")

    os.makedirs(output_dir, exist_ok=True)

    for f in os.listdir(malicious_files_dir):
        file_path = os.path.join(malicious_files_dir, f)

        if os.path.isfile(file_path):
            output_file_path = os.path.join(output_dir, f"[Radare2][{os.path.basename(file_path)}].txt")

            with open(output_file_path, "w") as o:
                subprocess.run(
                    ['r2', '-q', '-c', 'iI; iS; iz; ii; iE; is; isj; ic; icj; iEj; icns; agv; afv;', file_path],
                    stdout=o, stderr=subprocess.DEVNULL)

            with open(output_file_path, 'r') as file:
                content = file.read()
                if 'arch' not in content:
                    os.remove(output_file_path)


def is_private(ip):
    try:
        return "Yes" if ipaddress.ip_address(ip).is_private else "No"
    except ValueError:
        return None  # Handles cases where IP is None


# Function to convert Unix timestamp to readable format
def convert_timestamp(ts):
    try:
        return datetime.utcfromtimestamp(float(ts)).strftime('%Y-%m-%d %H:%M:%S')
    except (ValueError, TypeError):
        return None  # Handles cases where timestamp is missing


# Function to process PCAP file and save as CSV
def pcap_to_csv(pcap_file, work_dir_name):
    # Load the PCAP file
    packets = scapy.rdpcap(pcap_file)

    # Extract packet data
    data = []
    for pkt in packets:
        timestamp = convert_timestamp(pkt.time) if hasattr(pkt, 'time') else None
        source_ip = pkt[scapy.IP].src if pkt.haslayer(scapy.IP) else None
        dest_ip = pkt[scapy.IP].dst if pkt.haslayer(scapy.IP) else None

        packet_info = {
            "Timestamp": timestamp,
            "Source IP": source_ip,
            "Destination IP": dest_ip,
            "Protocol": pkt[scapy.IP].proto if pkt.haslayer(scapy.IP) else None,
            "Source Port": pkt.sport if pkt.haslayer(scapy.TCP) or pkt.haslayer(scapy.UDP) else None,
            "Destination Port": pkt.dport if pkt.haslayer(scapy.TCP) or pkt.haslayer(scapy.UDP) else None,
            "Size (Bytes)": len(pkt),
            "Source Private": is_private(source_ip),
            "Destination Private": is_private(dest_ip),
        }
        data.append(packet_info)

    # Convert to DataFrame
    df = pd.DataFrame(data)

    # Get the basename of the last directory in the path
    base_name = os.path.basename(os.path.normpath(work_dir_name))

    # Construct the CSV file path
    output_folder = os.path.join(work_dir_name, "final_report")
    csv_file = os.path.join(output_folder, f"{base_name}.csv")

    # Save to CSV
    df.to_csv(csv_file, index=False)


def process_intel_files(work_dir_name):
    # Define the input and output directories
    folder_path = os.path.join(work_dir_name, "files", "threat_intelligence_jsons")
    output_folder = os.path.join(work_dir_name, "final_report")
    os.makedirs(output_folder, exist_ok=True)  # Create the folder if it doesn't exist

    for filename in os.listdir(folder_path):
        if filename.endswith(".json"):
            file_path = os.path.join(folder_path, filename)
            output_csv = os.path.join(output_folder, filename.replace(".json", ".csv"))

            if filename.startswith("[HYBRID]"):
                hybrid_csv(file_path, output_csv)
            elif filename.startswith("[VT]"):
                vt_csv(file_path, output_csv)


def combine_intel_csvs(work_dir_name):
    directory = os.path.join(work_dir_name, "final_report")
    csv_files = glob.glob(os.path.join(directory, "*.csv"))
    dataframes = []

    for file in csv_files:
        file_name = os.path.basename(file)
        try:
            parts = file_name.split('][')
            if len(parts) == 3:
                source = parts[0].replace('[', '')
                malware_name = parts[1]
                hash_value = parts[2].replace(']', '').replace('.csv', '')
            else:
                print(f"Skipping file {file_name} due to unexpected filename format.")
                continue

            df = pd.read_csv(file)
            df['source'] = source
            df['malware_name'] = malware_name
            df['hash'] = hash_value
            dataframes.append(df)
        except Exception as e:
            print(f"Error processing file {file_name}: {e}")
            continue

    if not dataframes:
        print("No valid CSV files found.")
        return None

    combined_df = pd.concat(dataframes, ignore_index=True)
    all_columns = set(combined_df.columns)

    for column in all_columns:
        if column not in combined_df.columns:
            combined_df[column] = 'unavailable'

    combined_df = combined_df[['source', 'malware_name', 'hash'] + [col for col in combined_df.columns if
                                                                    col not in ['source', 'malware_name', 'hash']]]

    for file in csv_files:
        try:
            os.remove(file)
        except Exception as e:
            print(f"Error deleting file {file}: {e}")

    output_file = os.path.join(directory, "intel.csv")
    combined_df.to_csv(output_file, index=False)


def process_csv_with_ip_details(work_dir_name):
    folder_name = os.path.basename(work_dir_name)
    csv_file_name = f"final_report/{folder_name}.csv"
    file_path = os.path.join(work_dir_name, csv_file_name)
    df = pd.read_csv(file_path)

    # Initialize new columns
    columns = ["City Name", "Continent", "Country", "Latitude", "Longitude", "Timezone", "Postal Code", "State",
               "County/Province", "ISP", "Organization", "Connection Type"]
    for col in columns:
        df[f"Source {col}"] = ""
        df[f"Destination {col}"] = ""

    # Dictionary to cache IP lookup results
    ip_cache = {}

    # Function to fetch details for an IP from the API
    def get_ip_details(ip):
        if ip in ip_cache:
            return ip_cache[ip]
        url = f"https://api.findip.net/{ip}/?token={findip_key}"
        response = requests.get(url)

        if response.status_code == 200:
            try:
                data = response.json()
                if not data:
                    return {}
            except json.JSONDecodeError:
                return {}

            subdivisions = data.get("subdivisions", [])
            ip_info = {
                "City Name": data.get("city", {}).get("names", {}).get("en", ""),
                "Continent": data.get("continent", {}).get("names", {}).get("en", ""),
                "Country": data.get("country", {}).get("names", {}).get("en", ""),
                "Latitude": data.get("location", {}).get("latitude", ""),
                "Longitude": data.get("location", {}).get("longitude", ""),
                "Timezone": data.get("location", {}).get("time_zone", ""),
                "Postal Code": data.get("postal", {}).get("code", ""),
                "State": subdivisions[0]["names"].get("en", "") if len(subdivisions) > 0 and "names" in subdivisions[
                    0] else "",
                "County/Province": subdivisions[1]["names"].get("en", "") if len(subdivisions) > 1 and "names" in
                                                                             subdivisions[1] else "",
                "ISP": data.get("traits", {}).get("isp", ""),
                "Organization": data.get("traits", {}).get("organization", ""),
                "Connection Type": data.get("traits", {}).get("connection_type", "")
            }
            ip_cache[ip] = ip_info  # Cache result
            return ip_info
        return {}

    # Update DataFrame with IP details for public IPs
    for index, row in df.iterrows():
        if row["Source Private"] == "No":
            source_ip = row["Source IP"]
            source_ip_info = get_ip_details(source_ip)
            for col in columns:
                df.at[index, f"Source {col}"] = source_ip_info.get(col, "")

        if row["Destination Private"] == "No":
            destination_ip = row["Destination IP"]
            destination_ip_info = get_ip_details(destination_ip)
            for col in columns:
                df.at[index, f"Destination {col}"] = destination_ip_info.get(col, "")

    # Save updated CSV
    df.to_csv(file_path, index=False)


def abuseipdb_lookup(ip, cache):
    """Function to perform AbuseIPDB lookup with caching."""
    # Check if the result for the IP is already in the cache
    if ip in cache:
        return cache[ip]

    url = 'https://api.abuseipdb.com/api/v2/check'  # Define URL here
    querystring = {
        'ipAddress': ip,
        'maxAgeInDays': '90'
    }
    headers = {
        'Accept': 'application/json',
        'Key': abuseipdb_key
    }

    response = requests.get(url, headers=headers, params=querystring)

    # If the response is successful, process the data
    if response.status_code == 200:
        data = response.json().get('data', {})
        result = {
            "abuseConfidenceScore": data.get("abuseConfidenceScore", None),
            "isTor": data.get("isTor", None),
            "domain": data.get("domain", None)
        }
        # Store the result in cache before returning
        cache[ip] = result
        return result
    else:
        # If there's an error, return default None values and cache the result
        result = {
            "abuseConfidenceScore": None,
            "isTor": None,
            "domain": None
        }
        cache[ip] = result
        return result


def process_abuseipdb_data(work_dir_name):
    # Define the API endpoint and headers
    url = 'https://api.abuseipdb.com/api/v2/check'
    headers = {
        'Accept': 'application/json',
        'Key': abuseipdb_key
    }

    # Read the input CSV file
    folder_name = os.path.basename(work_dir_name)
    csv_file_name = f"final_report/{folder_name}.csv"
    file_path = os.path.join(work_dir_name, csv_file_name)
    df = pd.read_csv(file_path)

    # Initialize the new columns in the dataframe
    df['Source abuseConfidenceScore'] = None
    df['Destination abuseConfidenceScore'] = None
    df['Source isTor'] = None
    df['Destination isTor'] = None
    df['Source domain'] = None
    df['Destination domain'] = None

    # Initialize a cache dictionary to store results of IP lookups
    cache = {}

    # Iterate through each row in the dataframe and update the new columns
    for index, row in df.iterrows():
        # Source IP
        if row['Source Private'] == 'No':
            source_ip = row['Source IP']
            source_data = abuseipdb_lookup(source_ip, cache)
            df.at[index, 'Source abuseConfidenceScore'] = source_data['abuseConfidenceScore']
            df.at[index, 'Source isTor'] = source_data['isTor']
            df.at[index, 'Source domain'] = source_data['domain']

        # Destination IP
        if row['Destination Private'] == 'No':
            dest_ip = row['Destination IP']
            dest_data = abuseipdb_lookup(dest_ip, cache)
            df.at[index, 'Destination abuseConfidenceScore'] = dest_data['abuseConfidenceScore']
            df.at[index, 'Destination isTor'] = dest_data['isTor']
            df.at[index, 'Destination domain'] = dest_data['domain']

    # Overwrite the input CSV file with the updated dataframe
    output_file = os.path.join(work_dir_name, 'final_report', 'IP_data.csv')
    df.to_csv(output_file, index=False)
    if os.path.exists(file_path):
        os.remove(file_path)


def radare_to_csv_process_file(filepath):
    """Process a single file and return extracted data."""
    filename = os.path.basename(filepath)
    data = {
        "malware_name": filename,
        "source": "Radare",
        "binary_info": json.dumps(iIj_rdare(filepath)),
        "sections": json.dumps(iSj_rdare(filepath)),
        "symbols": json.dumps(isj_rdare(filepath)),
        "strings": json.dumps(izj_rdare(filepath)),
        "metadata": json.dumps(irj_rdare(filepath)),
    }
    return data


def radare_to_csv(work_dir_name):
    """Analyze all supported files in a directory and append results to CSV."""
    directory = os.path.join(work_dir_name, "files/malicious_files")
    csv_path = os.path.join(work_dir_name, "final_report/intel.csv")
    records = []
    SUPPORTED_EXTENSIONS = {".elf", ".so", ".bin", ".exe", ".dll", ".sys", ".macho", ".dylib", ".bundle", ".dex",
                            ".odex", ".apk", ".ipa", ".wasm"}
    for root, _, files in os.walk(directory):
        for file in files:
            if any(file.endswith(ext) for ext in SUPPORTED_EXTENSIONS):
                filepath = os.path.join(root, file)
                records.append(radare_to_csv_process_file(filepath))

    df_new = pd.DataFrame(records)
    if os.path.exists(csv_path):
        df_existing = pd.read_csv(csv_path)
        df_combined = pd.concat([df_existing, df_new], ignore_index=True)
    else:
        df_combined = df_new

    df_combined.to_csv(csv_path, index=False)


work_dir_name = None


def process_pcap(pcap_file):
    global work_dir_name  # Declare the variable as global
    work_dir_name = f"/content/case_files/{os.path.basename(pcap_file)}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    os.makedirs(work_dir_name, exist_ok=True)

    extract_files(pcap_file)
    detect_malware()
    calculate_hashes()
    hybrid_intel()
    vt_intel()
    rdare2_analysis()
    process_intel_files(work_dir_name)
    combine_intel_csvs(work_dir_name)
    pcap_to_csv(pcap_file, work_dir_name)
    process_csv_with_ip_details(work_dir_name)
    process_abuseipdb_data(work_dir_name)
    radare_to_csv(work_dir_name)

    final_report_loc = os.path.join(work_dir_name, "final_report")
    return final_report_loc