List of python tools which help executing remote ssh commands on multiple hosts in parallel as well getting the hosts from puppet master.

We assume that there is no puppet orchestration tools running on the remote clients, only standalone puppet agents which are triggered by executing remote ssh command from the puppet master host.
# puppet_clients.py

Creates local list of hostname and ssh port mapping(in case the ssh ports on hosts differs) e.g entrie in the output file is: "hostname portnumber"
# parssh.py

Executes in parallel commands using ssh on remote hosts. The tool uses the output from the puppet_clients.py to map the hostname with the ssh port number. If "-f" option is used, input file can be provided to read from. The input file needs to be in the format: "hostname portnumber", so the tool knows to which host and which ssh port to execute.
