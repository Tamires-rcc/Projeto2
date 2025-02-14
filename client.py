#!/usr/bin/env python3
"""
TFTPy - Este modulo implementa um cliente TFTP interativo e de linha de comando.
Ele também aceita opções para enviar e receber ficheiros pela linha de comando.

Este cliente aceita as seguintes opções:

Listar o servidor: python3 client.py [-p serv_port] server
Baixar (get) um ficheiro : python3 client.py get [-p serv_port] server remote_file [local_file]
Enviar (put) um ficheiro: python3 client.py put [-p serv_port] server local_file [remote_file]

Tamires Claro, 2024.
"""

import argparse
import cmd
import sys
import os
import socket
from tftp import (
    get_file,
    put_file,
    get_host_info,
    TFTPValueError,
    NetworkError,
    ProtocolError,
    Err,
)


class TFTPClient(cmd.Cmd):
    """Cliente TFTP Interativo."""
    
    prompt = "tftp client> "

    def __init__(self, server, port=69):
        super().__init__()
        try:
            self.server, self.server_ip = get_host_info(server)
            self.server_addr = (self.server_ip, port)
            print(f"Exchanging files with server '{self.server}' ({self.server_ip}) on port {port}")
        except socket.gaierror:
            print(f"Unknown server: {server}.")
            sys.exit(1)
        except Exception as e:
            print(f"Unexpected error: {e}")
            sys.exit(1)

    def do_get(self, args):
        """get remote_file: Baixar um arquivo do servidor."""
        params = args.split()
        if len(params) != 1:
            print("Usage: get <remote_file>")
            return

        remote_file = params[0]
        try:
            print(f"Attempting to get file '{remote_file}' from server.")
            socket.setdefaulttimeout(60)
            get_file(self.server_addr, remote_file)
            print(f"File '{remote_file}' downloaded successfully.")
        except FileNotFoundError:
            print(f"Error: File '{remote_file}' not found on server.")
        except socket.timeout:
            print("Error: Network timeout during transfer.")
        except (TFTPValueError, NetworkError, ProtocolError, Err) as e:
            print(f"Error: {e}")
        except Exception:
            print("Error: Server not responding. Exiting.")

    def do_put(self, args):
        """put local_file: Carregar um arquivo para o servidor."""
        params = args.split()
        if len(params) != 1:
            print("Usage: put <local_file>")
            return

        local_file = params[0]
        if not os.path.exists(local_file):
            print(f"Error: File '{local_file}' not found.")
            return

        try:
            print(f"Attempting to put file '{local_file}' to server.")
            socket.setdefaulttimeout(60)
            put_file(self.server_addr, local_file)
            print(f"File '{local_file}' uploaded successfully.")
        except FileNotFoundError:
            print(f"Error: File '{local_file}' not found on server.")
        except socket.timeout:
            print("Error: Network timeout during transfer.")
        except (TFTPValueError, NetworkError, ProtocolError, Err) as e:
            print(f"Error: {e}")
        except Exception:
            print("Error: Server not responding. Exiting.")

    def do_quit(self, args):
        """quit: saia do Cliente TFTP."""
        print("Exiting TFTP client. Goodbye!")
        return True

    def do_help(self, args):
        """help: Mostrar comandos disponíveis."""
        print("Commands:")
        print("  get <remote_file> - Download a file from the server")
        print("  put <local_file>  - Upload a file to the server")
        print("  quit              - Exit the TFTP client")


def non_interactive_mode(port, server, mode, source_file, dest_file=None):
    """Executa o cliente no modo não interativo."""
    try:
        print(f"Attempting {mode} operation for file '{source_file}' on server '{server}'...")
        try:
            server_ip, _ = get_host_info(server)
        except socket.gaierror:
            print(f"Unknown server: {server}.")
            sys.exit(1)
        except ValueError:
            print(f"Unknown server: {server}.")
            sys.exit(1)
        except Exception as e:
            print(f"Unexpected error when resolving server: {e}")
            sys.exit(1)

        server_addr = (server_ip, port)

        if mode == "get":
            local_file = dest_file if dest_file else source_file
            try:
                get_file(server_addr, source_file)
                print(f"File '{local_file}' downloaded successfully.")
            except ProtocolError as e:
                if "File not found" in str(e):
                    print(f"Error: File '{source_file}' not found on server.")
                else:
                    print(f"Protocol error: {e}")
                sys.exit(1)
            except FileNotFoundError:
                print(f"Error: File '{source_file}' not found on server.")
                sys.exit(1)
            except (TFTPValueError, NetworkError, Err) as e:
                print(f"Error: {e}")
                sys.exit(1)

        elif mode == "put":
            remote_file = dest_file if dest_file else source_file
            if not os.path.exists(source_file):
                print(f"Error: File '{source_file}' not found.")
                sys.exit(1)
            put_file(server_addr, source_file)
            print(f"File '{source_file}' uploaded successfully.")

    except socket.timeout:
        print("Error: Network timeout during transfer.")
        sys.exit(1)
    except Exception as e:
        print(f"Error: Server not responding. Exiting. ({e})")
        sys.exit(1)



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="TFTP Client")
    parser.add_argument("mode", choices=["get", "put"], nargs="?", help="Operation mode (get/put) for non-interactive mode")
    parser.add_argument("server", help="TFTP server address")
    parser.add_argument("source_file", nargs="?", help="Source file (only for non-interactive mode)")
    parser.add_argument("dest_file", nargs="?", help="Destination file (optional)")
    parser.add_argument("-p", "--port", type=int, default=69, help="TFTP server port (default: 69)")

    args = parser.parse_args()

    if args.mode and args.server and args.source_file:
        print(f"Running in non-interactive mode: {args.mode} {args.server} {args.source_file}")
        non_interactive_mode(args.port, args.server, args.mode, args.source_file, args.dest_file)

    elif args.server and not args.mode:
        print(f"Starting interactive mode with server {args.server}")
        TFTPClient(args.server, args.port).cmdloop()

    else:
        parser.print_help()






