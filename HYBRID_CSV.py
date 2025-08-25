import json
import csv

# List of keys is now defined globally
KEYS = [
    "classification_tags", "tags", "submissions", "machine_learning_models", "crowdstrike_ai", "job_id",
    "environment_id", "environment_description", "size", "type", "type_short", "target_url", "state",
    "error_type", "error_origin", "submit_name", "md5", "sha1", "sha256", "sha512", "ssdeep", "imphash",
    "entrypoint", "entrypoint_section", "image_base", "subsystem", "image_file_characteristics",
    "dll_characteristics", "major_os_version", "minor_os_version", "av_detect", "vx_family", "url_analysis",
    "analysis_start_time", "threat_score", "interesting", "threat_level", "verdict", "certificates",
    "is_certificates_valid", "certificates_validation_message", "domains", "compromised_hosts", "hosts",
    "total_network_connections", "total_processes", "total_signatures", "extracted_files", "file_metadata",
    "processes", "mitre_attcks", "network_mode", "signatures"
]

def find_all_first_level_dicts(data):
    if isinstance(data, dict):
        return [data]
    elif isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    return []

def extract_keys_first_level(data, keys):
    extracted_data = {key: [] for key in keys}  # Store values as lists initially
    
    first_level_dicts = find_all_first_level_dicts(data)
    
    for first_level_dict in first_level_dicts:
        for key in keys:
            if key in first_level_dict:
                value = first_level_dict[key]
                if value is not None:
                    if isinstance(value, list):
                        extracted_data[key].append(json.dumps(value))  # Encode lists as JSON strings
                    else:
                        extracted_data[key].append(str(value))
    
    for key in extracted_data:
        if not extracted_data[key]:  # If the list is empty, mark as ''
            extracted_data[key] = ""
        else:
            extracted_data[key] = ' | '.join(extracted_data[key])
    
    return extracted_data

def hybrid_csv(json_file, output_csv):
    with open(json_file, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    extracted_data = extract_keys_first_level(data, KEYS)
    
    with open(output_csv, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=KEYS)
        writer.writeheader()
        writer.writerow(extracted_data)


