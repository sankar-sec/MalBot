import os
import subprocess

os.makedirs("case_files", exist_ok=True)

def run_command(command, status_message):
    """Run a shell command and handle errors, printing only the status message."""
    print(status_message)  # Print the status message
    try:
        # Prepend DEBIAN_FRONTEND=noninteractive to avoid prompts
        process = subprocess.Popen(f"DEBIAN_FRONTEND=noninteractive {command}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        process.wait()  # Wait for the process to complete
        if process.returncode != 0:
            print(f"Error: Command failed with code {process.returncode}")
            exit(1)
    except Exception as e:
        print(f"Error: Failed to run command - {e}")
        exit(1)

def install_prerequisites():
    """Install required system packages and dependencies."""
    # Install Mono
    run_command("sudo apt install -y gnupg ca-certificates", "Installing Mono dependencies...")
    run_command("sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys 3FA7E0328081BFF6A14DA29AA6A19B38D3D831EF", "Adding Mono repository key...")
    run_command("echo 'deb https://download.mono-project.com/repo/ubuntu stable-focal main' | sudo tee /etc/apt/sources.list.d/mono-official-stable.list", "Adding Mono repository...")
    run_command("sudo apt update && sudo apt install -y mono-complete", "Installing Mono...")

    # Install Radare2
    os.makedirs("dependency", exist_ok=True)
    os.chdir("dependency")
    run_command("git clone https://github.com/radareorg/radare2.git", "Cloning Radare2...")
    os.chdir("radare2")
    run_command("sys/install.sh", "Installing Radare2...{This will take some time, be patient 🙂}")
    os.chdir("..")

    # Install Tshark
    run_command("echo 'wireshark-common wireshark-common/install-setuid boolean true' | sudo debconf-set-selections", "Configuring Tshark...")
    run_command("sudo apt install -y tshark", "Installing Tshark...")

    #Install ClamAV
    run_command("sudo apt install clamav","Installing ClamAV...")
    run_command("sudo freshclam","Updating Malware Database...")

    # Install .NET SDK
    run_command("wget https://dot.net/v1/dotnet-install.sh -O dotnet-install.sh", "Downloading .NET SDK installer...")
    run_command("bash dotnet-install.sh --channel 6.0 --install-dir $HOME/dotnet", "Installing .NET SDK...")
    os.environ["DOTNET_ROOT"] = f"{os.environ['HOME']}/dotnet"
    os.environ["PATH"] += f":{os.environ['HOME']}/dotnet"

    # Install Python Packages
    run_command("pip install scapy jinja2 fitz ollama numpy gradio tabula-py langchain rank_bm25 chromadb","Installing Python Packages")

    # Verify .NET installation
    try:
        subprocess.run(["dotnet", "--info"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except FileNotFoundError:
        print("Error: .NET SDK was not installed correctly.")
        exit(1)

def clone_and_build_networkminer():
    """Clone and build the NetworkMinerCLI project."""
    run_command("git clone https://github.com/mammo0/networkminer-cli.git", "Cloning NetworkMinerCLI...")
    # Build the project using .NET
    os.chdir("networkminer-cli")
    run_command("dotnet build NetworkMinerCLI.sln", "Building NetworkMinerCLI...")
    os.chdir("../..")

def setup():
    install_prerequisites()
    clone_and_build_networkminer()
