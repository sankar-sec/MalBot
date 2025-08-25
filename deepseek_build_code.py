import os
import sys
import requests
import json

from data_details import get_data_details

url = "http://localhost:11434/api/generate"

def generate_code_from_question(directory, question):
    intel_loc = os.path.join(directory, "intel.csv")
    ip_loc = os.path.join(directory, "IP_data.csv")

    intel_col_desc_str, ip_col_desc_str, intel_malware_names = get_data_details(intel_loc)

    prompt = '''
You are a Python pandas code generator. You retrieve data from csvs. You are given two CSV files: 

1. ''' + intel_loc + '''  
   - This CSV contains Intel of malware from various vendors and reverse-engineered binary codes.  
   - Currently, this CSV includes the following malwares: ''' + intel_malware_names + '''  

2. ''' + ip_loc + '''  
   - This CSV contains packet captures of malware in CSV format.  
   - Each row of this CSV represents a single packet transfer.  

Column descriptions:  
- For ''' + intel_loc + ''': ''' + intel_col_desc_str + '''  
- For ''' + ip_loc + ''': ''' + ip_col_desc_str + '''  

When asked a question, you must determine which CSV file to operate on.

You must follow these rules exactly (mandatory, non-negotiable):  

1. Treat all CSV data as raw text. It is not structured — do not attempt JSON, dictionaries, or any formatting.  
2. Use only very basic pandas operations (as taught in an introductory class). Keep code minimal.  
3. Never access data by row numbers. Only use column names.  
4. Many cells are empty — when asked for data (e.g., malware X under column A), return all mentions of X in that column.  
5. Always concatenate multiple relevant columns when retrieving data. Never output a single column alone.  
6. Be extremely precise: if a specific value is requested, identify the most appropriate column(s) and retrieve exactly that.  
7. Do not use regex, string processing, delimiters, or complex filtering — only retrieve columns as-is.  
8. Never output column names — only return the contents.  
9. Do not create slices of a DataFrame and then modify them; always operate on the original DataFrame or use .loc for filtering and assignment, and ensure columns exist before referencing them.  
10. Always filter or modify columns on the original DataFrame (or use .loc) instead of a slice, and ensure the column exists before referencing it to avoid warnings and KeyErrors.  
11. Do not process or clean NaN values — include them in output.  
12. Never add unnecessary arguments or operations.  
13. If you make a function, make sure you call and return it.  
14. You must follow the user’s request literally and specifically.  
15. You are super strict — there is no exception. Follow every rule above exactly.  
16. You will only produce Python code — no explanations, no markdown, no comments, no formatting, no intros, no outros. Your code must retrieve specific information exactly as requested.

You need to write a code to retreive appropriate data from the CSV that can answer the below question
''' + question + '''
'''

    payload = {
        "model": "deepseek-coder-v2:16b",
        "prompt": prompt,
        "options": {
            "num_ctx": 15000
        }
    }

    response = requests.post(url, json=payload, stream=True)

    output_text = ""
    for line in response.iter_lines():
        if line:
            data = json.loads(line.decode("utf-8"))
            if "response" in data:
                output_text += data["response"]

    # strip ```python ``` wrappers if they exist
    output_text = output_text.replace("```python", "").replace("```", "").strip()
    return output_text

if __name__ == "__main__":
    directory = os.getcwd()
    question = "What are the functions imported by ghost.exe?"
    code = generate_code_from_question(directory, question)
    print(code)
