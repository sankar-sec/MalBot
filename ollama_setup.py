import subprocess
print("Setting up LLMs")
subprocess.run("curl -fsSL https://ollama.com/install.sh | sh", shell=True, check=True)
subprocess.run("nohup ollama serve > ollama.log 2>&1 &", shell=True, check=True)
subprocess.run("ollama pull llama3.1:8b", shell=True, check=True)
subprocess.run("ollama pull deepseek-coder-v2:16b",shell=True, check=True)
print("LLMs are setup!")