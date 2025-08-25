import json
import csv

# List of keys to extract
KEYS = [
    "last_modification_date", "magic", "sha1", "last_analysis_results", "authentihash", "type_extension", 
    "tlsh", "unique_sources", "type_description", "detectiteasy", "reputation", "filecondis", "signature_info", 
    "tags", "vhash", "creation_date", "size", "md5", "first_submission_date", "sha256", "magika", 
    "last_submission_date", "total_votes", "pe_info", "type_tags", "last_analysis_date", "meaningful_name", 
    "trid", "times_submitted", "sandbox_verdicts", "names", "popular_threat_classification", 
    "crowdsourced_yara_results", "last_analysis_stats", "ssdeep", "type_tag"
]

def extract_keys_from_attributes(data, keys):
    extracted_data = {key: [] for key in keys}  # Store values as lists initially
    
    # Check if the 'data' is a dictionary and contains the 'attributes' key
    if isinstance(data, dict) and "attributes" in data:
        attributes = data["attributes"]
        if isinstance(attributes, dict):  # Ensure that attributes is a dictionary
            for key in keys:
                if key in attributes:
                    value = attributes[key]
                    if value is not None:
                        if isinstance(value, list):
                            extracted_data[key].append(json.dumps(value))  # Encode lists as JSON strings
                        else:
                            extracted_data[key].append(str(value))
        else:
            # If 'attributes' is not found or is not a dictionary, mark all as 'Unavailable'
            for key in keys:
                extracted_data[key].append("")
    else:
        # If 'data' doesn't have 'attributes', mark all as 'Unavailable'
        for key in keys:
            extracted_data[key].append("")
    
    # If no data was extracted for a key, mark as 'Unavailable'
    for key in extracted_data:
        if not extracted_data[key]:
            extracted_data[key] = ""
        else:
            extracted_data[key] = ' | '.join(extracted_data[key])
    
    return extracted_data

def vt_csv(json_file, output_csv):
    with open(json_file, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    # Extract 'data' object
    if isinstance(data, dict) and "data" in data:
        data = data["data"]  # Extract the 'data' object, which contains 'attributes'
        
    # Extract the required keys from the 'attributes' in 'data'
    extracted_data = extract_keys_from_attributes(data, KEYS)
    
    # Write the extracted data to a CSV file
    with open(output_csv, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=KEYS)
        writer.writeheader()
        writer.writerow(extracted_data)

