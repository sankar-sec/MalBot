import os
import subprocess
import json

def iIj_rdare(file_path):
    if not os.path.isfile(file_path):
        return "File not found."
    
    try:
        result = subprocess.run(['r2', '-q', '-c', 'iI', file_path], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        formatted_output = " - " .join(f"({line.split()[0]} : {' '.join(line.split()[1:])})" for line in result.stdout.strip().split('\n') if line)
        return formatted_output
    except Exception as e:
        return f"Error running analysis: {str(e)}"


def isj_rdare(file_path):
    if not os.path.isfile(file_path):
        return "File not found."
    
    try:
        result = subprocess.run(['r2', '-q', '-c', 'isj', file_path], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        imports = json.loads(result.stdout.strip())
        filtered_output = [{"name": imp["name"], "flagname": imp["flagname"], "realname": imp["realname"], "type": imp["type"], "is_imported": imp["is_imported"]} for imp in imports]
        return json.dumps(filtered_output, indent=4)
    except Exception as e:
        return f"Error running analysis: {str(e)}"

def iSj_rdare(file_path):
    if not os.path.isfile(file_path):
        return "File not found."
    
    try:
        result = subprocess.run(['r2', '-q', '-c', 'iSj', file_path], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        sections = json.loads(result.stdout.strip())
        filtered_output = [{"name": sec["name"], "size": sec["size"], "vsize": sec["vsize"], "perm": sec["perm"]} for sec in sections]
        return json.dumps(filtered_output, indent=4)
    except Exception as e:
        return f"Error running analysis: {str(e)}"

def izj_rdare(file_path):
    if not os.path.isfile(file_path):
        return "File not found."
    
    try:
        result = subprocess.run(['r2', '-q', '-c', 'izj', file_path], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        
        # Parse the JSON output from 'izj'
        items = json.loads(result.stdout.strip())
        
        # Filter for the desired fields: "section", "type", "string", "size", and "length"
        filtered_output = [{"section": item["section"], "type": item["type"], "string": item["string"], "size": item["size"], "length": item["length"]} for item in items]
        
        return json.dumps(filtered_output, indent=4)  # Return the filtered data as formatted JSON
    except Exception as e:
        return f"Error running analysis: {str(e)}"

def irj_rdare(file_path):
    if not os.path.isfile(file_path):
        return "File not found."
    
    try:
        result = subprocess.run(['r2', '-q', '-c', 'irj', file_path], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        
        # Parse the JSON output from 'irj'
        output_data = json.loads(result.stdout.strip())
        
        # Filter for the desired fields: "name", "type", and "is_ifunc"
        filtered_output = [{"name": item["name"], "type": item["type"], "is_ifunc": item.get("is_ifunc", "N/A")} for item in output_data]
        
        return json.dumps(filtered_output, indent=4)  # Return the filtered data as formatted JSON
    except Exception as e:
        return f"Error running analysis: {str(e)}"

