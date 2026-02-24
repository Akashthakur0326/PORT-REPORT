STUDY CASE SYSTEM

TO RUN THE VICTIM CONTAINER WITH MANY EXPLOITABLE THINGS 
docker run --name victim -it -d tleemcjr/metasploitable2:latest sh -c "/bin/services.sh && bash"
-it
    Two flags combined:
    -i → Keeps STDIN open (interactive)
    -t → Allocates a pseudo-terminal (so you get a shell-like experience)

    sh -c "/bin/services.sh && bash"
        This tells the container what command to run when it starts.
        sh -c
        Runs a command string inside a shell.
        "/bin/services.sh && bash"
            This does two things:
            /bin/services.sh
            Starts vulnerable services inside Metasploitable (FTP, SSH, web server, etc.)
            && bash
            After services start, it launches a Bash shell
            Keeps the container running

docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' victim 
GIVES THE IP USED BY THE CONTAINER -- 172.17.0.3

By default, Docker creates a virtual network:
        Network name: bridge
        Subnet: 172.17.0.0/16
        Gateway: 172.17.0.1

Your victim container IP: 172.17.0.3 (That IP lives inside Docker’s virtual network)

docker run --rm -it nicolaka/netshoot nmap -sV 172.17.0.3
    Running a temporary Docker container that executes nmap to scan another container at 172.17.0.3

    -sV --This tells nmap to:Perform service version detection
    Nmap from Inside Docker
    When you run: docker run --rm -it nicolaka/netshoot nmap -sV 172.17.0.3
    You are launching: nicolaka/netshoot --This container is attached to the same bridge network.



//REMEMBER 
-- the tools i will give the llm are to call the nvd api and the tool to hit DB and get attack pattern and a tool to access chroma DB and get text to send tollm on prevention measue a decide we can do is that decide bw TBD 

The Strategy: LLM as the "Planner"
You are moving into Agentic Workflow territory. Instead of hardcoding which exploit runs, the LLM will analyze the CVE description and pick the best "Tool" (Template) for the job.

The Workflow:

        Input: CVE-2011-2523 (after resseracher.py) + "Backdoor in vsftpd 2.3.4..."

        LLM Decision: "This is a socket-based backdoor. Use socket_raw."(from the templates define)

        Execution: Your code pulls the socket_raw logic, sends the payload, and checks for a result.(on the vistim container defibed)

        Validation: Your validate_evidence function confirms the result.(based on template and validator.py)

TO DO 
--make a template for attck scripts and validate pattern
--make a DB with all the seen CVE and what attck classification they are in (make this predefined Db using colab and gemini)- make this local as we want that atleast those cpe which are vulnerable in the default container to work so make DB on those cpe
-- make a agentic which hits that DB and gets then gets the attack patter for the cpe/cve if not hit the tool to call nvd api and get description and all and classify it based on the attck template and assign that template to it 
-- make a attck.py which attacks the victim on that template 
-- get the result on previous step and validate it using validate.py
-- see if result works if the exploit is seen go the inference step of hitting chroma DB and giving the remedies to current problems 
SO SET UP -- colab attck.py validator.py and a DB which is temporarliy at seed.py and set up a docker postgres in docker-compose
make a tool which searches the DB if not from the inspiartion hit DB and if cpe not there hit nvd and llm 
then set up attck.py to attck the victim based on decided attack template and then validate the response using validate.py



port-report/
├── .venv/                      # Managed automatically by uv
├── .python-version             # Locks your Python version (e.g., 3.13)
├── pyproject.toml              # The SINGLE source of truth for dependencies
├── README.md
├── docker-compose.yml          # (We will build this later)
├── backend.Dockerfile          # Nmap + FastAPI container setup, optimized for uv
└── src/
    └── port_report/            # Your globally installable package namespace
        ├── __init__.py
        ├── api/                # Replaces the old 'backend' folder
        │   ├── __init__.py
        │   ├── main.py         # FastAPI entry point
        │   └── core/
        │       ├── __init__.py
        │       └── scanner.py  # Your Nmap logic
        └── ui/                 # Replaces the old 'frontend' folder
            ├── __init__.py
            └── app.py          # Streamlit UI