import pandas as pd

def get_data_details(loc):
    # intel column descriptions
    intel_col_desc = {
        "malware_name": "The name of the malware.",
        "size": "The size of the malware in bytes, useful for understanding its footprint and operational characteristics.",
        "md5": "MD5 hash of the file, used for identification and integrity verification.",
        "sha1": "SHA1 hash of the file, providing a cryptographic fingerprint for tracking and correlation.",
        "sha256": "SHA256 hash of the file, ensuring data integrity and supporting threat intelligence operations.",
        "ssdeep": "SSDEEP fuzzy hash for similarity-based file comparison and detection of malware variants.",
        "last_analysis_results": "Aggregated antivirus engine results, providing insights into malware behavior and detection.",
        "type_extension": "The file extension of the malware, assisting in threat identification and IOC correlation.",
        "tlsh": "TLSH hash for efficient file comparison and detection of identical or similar malware.",
        "detectiteasy": "Metadata about file types and compilation tools, aiding reverse engineering and threat hunting.",
        "vhash": "Variant hash values for tracking and comparing malware samples across platforms.",
        "pe_info": "Metadata and behavioral indicators from PE32 files, including timestamps, imports, sections, and compiler details.",
        "sandbox_verdicts": "Structured sandbox analysis results with threat categorization and confidence metrics.",
        "names": "Alternative or associated names for the malware, helping track variants and evasion attempts.",
        "popular_threat_classification": "Threat categories and suggested labels, providing an overview of malware behavior and prevalence.",
        "crowdsourced_yara_results": "YARA rule match results, summarizing known behaviors and threat indicators.",
        "binary_info": "Binary metadata including architecture, compilation, OS, and security features, aiding reverse engineering.",
        "sections": "Information on sections within the binary, including names, sizes, and permissions, supporting file forensics.",
        "symbols": "Imported functions and libraries, revealing API usage and potential malicious capabilities.",
        "strings": "Extracted function names, constants, and related information from binaries for behavioral analysis.",
        "metadata": "Additional binary analysis data, including byte patterns, memory addresses, and disassembled instructions."
    }

    # ip column descriptions
    ip_col_desc = {
        "Timestamp": {
            "explanation": "The exact date and time a network packet was captured.",
            "data_type": "string (datetime)",
            "value_type": "multiple values",
            "example": "2020-02-14 21:47:58"
        },
        "Source IP": {
            "explanation": "The IP address from which the network packet originated.",
            "data_type": "string",
            "value_type": "multiple values",
            "example": "192.168.248.100"
        },
        "Destination IP": {
            "explanation": "The IP address to which the network packet was sent.",
            "data_type": "string",
            "value_type": "multiple values",
            "example": "13.107.21.200"
        },
        "Protocol": {
            "explanation": "The network protocol used for the communication (e.g., TCP, UDP, ICMP).",
            "data_type": "float",
            "value_type": "multiple values",
            "example": "6.0"
        },
        "Source Port": {
            "explanation": "The port number on the source machine used for the communication.",
            "data_type": "float",
            "value_type": "multiple values",
            "example": "49595.0"
        },
        "Destination Port": {
            "explanation": "The port number on the destination machine used for the communication.",
            "data_type": "float",
            "value_type": "multiple values",
            "example": "443.0"
        },
        "Size (Bytes)": {
            "explanation": "The size of the network packet in bytes.",
            "data_type": "int",
            "value_type": "multiple values",
            "example": "54"
        },
        "Source Private": {
            "explanation": "Indicates if the source IP address is a private IP.",
            "data_type": "string",
            "value_type": "binary",
            "example": "Yes"
        },
        "Destination Private": {
            "explanation": "Indicates if the destination IP address is a private IP.",
            "data_type": "string",
            "value_type": "binary",
            "example": "No"
        },
        "Source City Name": {
            "explanation": "The city name associated with the source IP address.",
            "data_type": "string",
            "value_type": "multiple values",
            "example": "Montreal"
        },
        "Destination City Name": {
            "explanation": "The city name associated with the destination IP address.",
            "data_type": "string",
            "value_type": "multiple values",
            "example": "Ashburn"
        },
        "Source Continent": {
            "explanation": "The continent associated with the source IP address.",
            "data_type": "string",
            "value_type": "multiple values",
            "example": "North America"
        },
        "Source Country": {
            "explanation": "The country associated with the source IP address.",
            "data_type": "string",
            "value_type": "multiple values",
            "example": "Canada"
        },
        "Destination Country": {
            "explanation": "The country associated with the destination IP address.",
            "data_type": "string",
            "value_type": "multiple values",
            "example": "United States"
        },
        "Source Latitude": {
            "explanation": "The geographic latitude of the source IP address.",
            "data_type": "float",
            "value_type": "multiple values",
            "example": "45.5019"
        },
        "Destination Latitude": {
            "explanation": "The geographic latitude of the destination IP address.",
            "data_type": "float",
            "value_type": "multiple values",
            "example": "39.0438"
        },
        "Source Longitude": {
            "explanation": "The geographic longitude of the source IP address.",
            "data_type": "float",
            "value_type": "multiple values",
            "example": "-73.5674"
        },
        "Destination Longitude": {
            "explanation": "The geographic longitude of the destination IP address.",
            "data_type": "float",
            "value_type": "multiple values",
            "example": "-77.4874"
        },
        "Source Timezone": {
            "explanation": "The timezone associated with the source IP address.",
            "data_type": "string",
            "value_type": "multiple values",
            "example": "America/Toronto"
        },
        "Destination Timezone": {
            "explanation": "The timezone associated with the destination IP address.",
            "data_type": "string",
            "value_type": "multiple values",
            "example": "America/Chicago"
        },
        "Source Postal Code": {
            "explanation": "The postal code associated with the source IP address.",
            "data_type": "string",
            "value_type": "multiple values",
            "example": "H4X"
        },
        "Destination Postal Code": {
            "explanation": "The postal code associated with the destination IP address.",
            "data_type": "string",
            "value_type": "multiple values",
            "example": "20149"
        },
        "Source State": {
            "explanation": "The state or province of the source IP address.",
            "data_type": "string",
            "value_type": "multiple values",
            "example": "Quebec"
        },
        "Destination State": {
            "explanation": "The state or province of the destination IP address.",
            "data_type": "string",
            "value_type": "multiple values",
            "example": "Virginia"
        },
        "Source County/Province": {
            "explanation": "The county or province of the source IP address.",
            "data_type": "string",
            "value_type": "multiple values",
            "example": "Montréal"
        },
        "Destination County/Province": {
            "explanation": "The county or province of the destination IP address.",
            "data_type": "string",
            "value_type": "multiple values",
            "example": "Loudoun"
        },
        "Source ISP": {
            "explanation": "The Internet Service Provider of the source IP address.",
            "data_type": "string",
            "value_type": "multiple values",
            "example": "Microsoft Corporation"
        },
        "Destination ISP": {
            "explanation": "The Internet Service Provider of the destination IP address.",
            "data_type": "string",
            "value_type": "multiple values",
            "example": "Microsoft Corporation"
        },
        "Source Connection Type": {
            "explanation": "The connection type of the source IP address.",
            "data_type": "string",
            "value_type": "multiple values",
            "example": "Corporate"
        },
        "Source abuseConfidenceScore": {
            "explanation": "A score indicating the confidence level that the source IP is an abuser (100 is high, 0 is low).",
            "data_type": "float",
            "value_type": "multiple values",
            "example": "0.0"
        },
        "Destination abuseConfidenceScore": {
            "explanation": "A score indicating the confidence level that the destination IP is an abuser (100 is high, 0 is low).",
            "data_type": "float",
            "value_type": "multiple values",
            "example": "0.0"
        },
        "Source isTor": {
            "explanation": "Indicates if the source IP address is part of the Tor network.",
            "data_type": "string",
            "value_type": "binary",
            "example": "False"
        },
        "Destination domain": {
            "explanation": "The domain name associated with the destination IP address.",
            "data_type": "string",
            "value_type": "multiple values",
            "example": "microsoft.com"
        }
    }

    # Format descriptions into strings
    intel_col_desc_str = "".join(f"< `{k}`: {v} >" for k, v in intel_col_desc.items())
    ip_col_desc_str = "".join(f"< `{k}`: {v} >" for k, v in ip_col_desc.items())

    # Read malware names from intel.csv inside given location
    intel_csv_path = loc
    df = pd.read_csv(intel_csv_path)
    intel_malware_names = ', '.join(df['malware_name'].dropna().unique())

    return intel_col_desc_str, ip_col_desc_str, intel_malware_names
