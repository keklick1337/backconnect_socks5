# Backconnect SOCKS5

A simple example of a **backconnect** architecture for SOCKS5 proxy.  
The server (`server_socks5`) runs on a publicly accessible host and waits for a client located behind NAT (`client_socks5`).  
Once the client connects to the server, the server can “reverse” traffic back to the SOCKS5 on the client side, bypassing NAT.

## Main Idea

1. **Server part** listens on two ports:
   - **Control Port** (specified with `-c`): for the client that is behind NAT to connect.
   - **SOCKS Port** (specified with `-S`): the SOCKS5 proxy port that external users can use.

2. **Client** (behind NAT) periodically tries to connect to the server on the **Control Port**.  
   If the connection is successful, an XOR handshake is performed, and the client then keeps the connection alive (sending keep-alive packets and handling commands).

3. When the **server**’s SOCKS5 receives a **CONNECT** request, the server sends a `C` command to the client with the target IP and port. Upon receiving this command, the client establishes a local connection to that target (which is presumably in the internal network) and links it to the server through the already established tunnel.

Thus, a remote machine can act as a SOCKS5 proxy, effectively forwarding connections to services behind NAT.

## Building

### Linux / macOS
1. Make sure you have a C++ compiler (g++ or clang++) installed.
2. Make the build script executable and run it:
   ```bash
   chmod +x compile_linux_macos.sh
   ./compile_linux_macos.sh
   ```
3. You will get two binaries: `server_socks5` and `client_socks5`.

### Windows (MSVC)
1. Install Microsoft Visual C++ (CL).
2. Run in the command prompt:
   ```bat
   compile_win_msvc.bat
   ```
3. You will get `server_socks5.exe` and `client_socks5.exe`.

## Usage

Below are the command-line parameters for both **server** and **client**.

### Server (server_socks5)
```
server_socks5 -c <control_port> -S <socks_port> -x <xor_key> [-u <user> -p <pass>] [-d]
```
- `-c <control_port>` — port on which the server listens for the NAT client.
- `-S <socks_port>` — port for the local SOCKS5 proxy (externally available).
- `-x <xor_key>` — XOR key for encrypting control messages.
- `-u <user>` and `-p <pass>` — (optional) if provided, SOCKS5 will require username/password authentication.
- `-d` — enable debug output (verbose logging).

**Example**:
```bash
./server_socks5 -c 9000 -S 1080 -x secret -u test -p 123 -d
```
In this example:
- The server waits for the NAT client on port `9000`.
- The SOCKS5 proxy is on port `1080`.
- XOR key is `secret`.
- SOCKS5 requires authentication (username `test`, password `123`).
- Debug mode is enabled.

### Client (client_socks5)
```
client_socks5 -s <server_ip> -c <control_port> -x <xor_key> [-d]
```
- `-s <server_ip>` — IP or domain name of the server (the public host).
- `-c <control_port>` — the same port specified on the server with `-c`.
- `-x <xor_key>` — the same XOR key as on the server.
- `-d` — enable debug output.

**Example**:
```bash
./client_socks5 -s 1.2.3.4 -c 9000 -x secret -d
```
The client will attempt to connect to `1.2.3.4:9000` and use the XOR key `secret`.  

Once the connection is established, the server will manage the tunnels, and the client will automatically connect to the requested local resources behind NAT.

## How It Works

1. **Server** runs on a public server:
   - It listens on the **Control Port** (e.g., `9000`) for inbound connections from the NAT client.
   - It listens on the **SOCKS Port** (e.g., `1080`) for SOCKS5 connections.
2. **Client** behind NAT attempts to connect out to the server at `Control Port`. Upon success:
   - An XOR handshake is performed (to verify the key).
   - The client “holds” the connection, sending keep-alives (`K`) to avoid disconnection.
3. When the server’s SOCKS5 (on port `1080`) receives a **CONNECT** request:
   - The server sends a `C` command over the control channel to the client, instructing it to “connect to 1.2.3.4:2222” (for example).
   - The server opens an ephemeral port and accepts a connection “from the other side”.
4. The client then connects locally to `1.2.3.4:2222` (behind NAT) and relays the data back to the server through the already established control channel.

Hence, SSH, RDP, web server, or any other service listening in the internal network becomes accessible through the SOCKS5 proxy on the server.

## Important Notes

- By default, **XOR**-based encryption is not strong cryptographic protection. It’s only a basic obfuscation technique. For real security, consider using a VPN or TLS-based tunnels.
- If `-u`/`-p` flags are specified at **server** startup, SOCKS5 authentication (username/password) is required. This does not affect the server–client (control) channel, which only checks for a matching XOR key.

## Debugging

- The `-d` (debug) flag will show more detailed logs, including connection failures, network errors, and so on.

## License & Disclaimer

This code is provided “as is” for educational purposes.  
The authors and repository owners are not responsible for any consequences of its use.  
Use it only for legitimate purposes, in a legal manner!