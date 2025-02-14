""" Esse módulo lida com todas as funcionalidades relacionadas ao TFTP como:
Estruturas de dados, Definições de pacotes, Métodos e operações de protocolo.

Tamires Claro,2024.
"""
import ipaddress
import re
import socket as socket_mod
from socket import socket, AF_INET,SOCK_DGRAM
import string
import struct

#################################################################################
##
##             PROTOCOL CONSTANTS AND TYPES
##
#################################################################################

MAX_DATA_LEN = 512          # bytes
DEFAULT_MODE = 'octet'      # transfer mode (one of 'octet', 'netascii',etc.)
INACTIVITY_TIMEOUT = 25.0   # Default timeout for inactivity in seconds
DEFAULT_BUFFER_SIZE = 8192  # Buffer size for receiving packets

# TFTP message opcodes
RRQ = 1       # Read ReQuest
WRQ = 2       # Write ReQuest
DAT = 3       # DATa transfer
ACK = 4       # ACKnowledge
ERR = 5       # Error packet; o que o servidor responde se uma leitura/escrita
              # não pode ser processado, erros de leitura e gravação durante o arquivo
              # transmissão também faz com que esta mensagem seja enviada, e
              # a transmissão é então encerrada. O número de erro fornece um 
              # código de erro numérico, seguido por uma mensagem de erro ASCII que
              # pode conter sistemas operacionais adicionais específicos
              # informação

ERR_NOT_DEFINED = 0         # Custom error
ERR_FILE_NOT_FOUND = 1
ERR_ACCESS_VIOLATION = 2
ERR_DISK_FULL = 3
ERR_ILLEGAL_OPERATION = 4
ERR_UNKNOWN_TRANSFER_ID = 5
ERR_FILE_ALREADY_EXISTS = 6
ERR_NO_SUCH_USER = 7

ERROR_MESSAGES = {
    ERR_NOT_DEFINED: 'Not defined, see error message (if any).',
    ERR_FILE_NOT_FOUND: 'File not found.',
    ERR_ACCESS_VIOLATION: 'Access violation',
    ERR_DISK_FULL: 'Disk full or allocation exceeded.',
    ERR_ILLEGAL_OPERATION: 'Illegal TFTP operation.',
    ERR_UNKNOWN_TRANSFER_ID: 'Unknown transfer ID.',
    ERR_FILE_ALREADY_EXISTS: 'File already exists.',
    ERR_NO_SUCH_USER: 'No such user.',
}

INET4Address = tuple[str, int]          #TCP/UDP address => IPv4 and port

############################################################################
##
##          SEND AND RECEIVE FILES
##
############################################################################

def get_file(server_addr: INET4Address, filename: str):
    """
    Obter o arquivo remoto fornecido por 'nome do arquivo' através de uma conexão TFTP RRQ
    para o servidor remoto em 'server_addr'.
    """
    with socket(AF_INET, SOCK_DGRAM) as sock:
        sock.settimeout(INACTIVITY_TIMEOUT)
        sock.bind(("", 0))
        
        with open(filename, 'wb') as out_file:
            rrq = pack_rrq(filename)
            next_block_number = 1
            sock.sendto(rrq, server_addr)

            while True:
                packet, new_server_addr = sock.recvfrom(DEFAULT_BUFFER_SIZE)
                server_addr = new_server_addr
                opcode = unpack_opcode(packet)

                if opcode == DAT:
                    block_number, data = unpack_dat(packet)
                    if block_number == next_block_number:
                        out_file.write(data)
                        out_file.flush()
                        next_block_number += 1

                        ack = pack_ack(block_number)
                        sock.sendto(ack, server_addr)

                        if len(data) < MAX_DATA_LEN:
                            break
                            
                elif opcode == ERR:
                    error_code, error_msg = unpack_err(packet)
                    raise Err(error_code, error_msg)
                    
                else:
                    error_msg = f'Invalid packet opcode: {opcode}. Expecting {DAT=}'
                    raise ProtocolError(error_msg)

def put_file(server_addr: INET4Address, filename: str):
    """
    Envia um arquivo para o servidor remoto através de uma conexão TFTP WRQ.
    """
    with socket(AF_INET, SOCK_DGRAM) as sock:
        sock.settimeout(INACTIVITY_TIMEOUT)
        sock.bind(("", 0))
        
        with open(filename, 'rb') as in_file:
            wrq = pack_wrq(filename)
            sock.sendto(wrq, server_addr)
            packet, new_server_addr = sock.recvfrom(DEFAULT_BUFFER_SIZE)
            server_addr = new_server_addr
            
            opcode = unpack_opcode(packet)
            if opcode != ACK:
                error_code, error_msg = unpack_err(packet)
                raise Err(error_code, error_msg)
            
            block_number = 1
            while True:
                data = in_file.read(MAX_DATA_LEN)
                data_packet = pack_dat(block_number, data)
                sock.sendto(data_packet, server_addr)
                
                packet, _ = sock.recvfrom(DEFAULT_BUFFER_SIZE)
                opcode = unpack_opcode(packet)
                
                if opcode != ACK:
                    error_code, error_msg = unpack_err(packet)
                    raise Err(error_code, error_msg)
                
                received_block_number = unpack_ack(packet)
                if received_block_number != block_number:
                    raise ProtocolError(f'Invalid ACK block number: {received_block_number}')
                
                if len(data) < MAX_DATA_LEN:
                    break
                
                block_number += 1

#############################################################################
##
##           PACKET PACKING AND UNPACKING
##
#############################################################################

def pack_rrq(filename: str, mode = DEFAULT_MODE) ->bytes:
    return _pack_rq(RRQ, filename, mode)

def pack_wrq(filename: str, mode = DEFAULT_MODE) ->bytes:
    return _pack_rq(WRQ, filename, mode)

def _pack_rq(opcode: int,filename: str, mode = DEFAULT_MODE) -> bytes:
    if not is_ascii_printable(filename):
        raise TFTPValueError(f'Invalid filename: {filename}. Not ASCII printable')
    filename_bytes = filename.encode() + b'\x00'
    mode_bytes = mode.encode() + b'\x00'
    rrq_fmt = f'!H{len(filename_bytes)}s{len(mode_bytes)}s'
    return struct.pack(rrq_fmt, opcode, filename_bytes, mode_bytes)

def unpack_rqq(packet: bytes) -> tuple[str, str]:
    return _unpack_rq(RRQ, packet)

def unpack_wrq(packet: bytes) -> tuple[str, str]:
    return _unpack_rq(WRQ, packet)

def _unpack_rq(expected_opcode: int, packet: bytes) -> tuple[str, str]:
    received_opcode = unpack_opcode(packet)
    if received_opcode != expected_opcode:
        raise TFTPValueError(f'Invalid opcode: {received_opcode}. Expected {expected_opcode}')
    delim_pos = packet.index(b'\x00', 2)
    filename = packet[2:delim_pos].decode()
    mode = packet[delim_pos + 1:-1].decode()
    return filename, mode

def unpack_opcode(packet : bytes) -> int:
    opcode, *_ = struct.unpack('!H', packet[:2])
    if opcode not in (RRQ, WRQ, DAT, ACK, ERR):
        raise TFTPValueError(f'Invalid opcode: {opcode}')
    return opcode

def pack_dat(block_number: int, data: bytes) -> bytes:
    if len(data) > MAX_DATA_LEN:
        raise TFTPValueError(f'Data length exceeds {MAX_DATA_LEN} bytes')
    fmt = f'!HH{len(data)}s'
    return struct.pack(fmt, DAT, block_number, data)

def unpack_dat(packet: bytes) -> tuple[int, bytes]:
    opcode, block_number = struct.unpack('!HH', packet[:4])
    if opcode != DAT:
        raise TFTPValueError(f'Invalid opcode: {opcode}')
    return block_number, packet[4:]  # Fixed to return actual data

def pack_ack(block_number: int) -> bytes:
    return struct.pack('!HH', ACK, block_number)

def unpack_ack(packet:bytes) -> int:
    if len(packet) > 4:
        raise ValueError(f'Invalid packet length: {len(packet)}') 
    return struct.unpack('!H', packet[2:4])[0]

def pack_err(error_num: int, error_msg: str)-> bytes:
    if not is_ascii_printable(error_msg):
        raise TFTPValueError(f'Invalid error message: {error_msg}. Not ASCII printable')
    error_msg_bytes = error_msg.encode() + b'\x00'
    fmt = f'!HH{len(error_msg_bytes)}s'
    return struct.pack(fmt, ERR, error_num, error_msg_bytes)

def unpack_err(packet: bytes) -> tuple[int, str]:
    opcode, error_num, error_msg = struct.unpack(f'!HH{len(packet)-4}s', packet)
    if opcode != ERR:
        raise ValueError(f'Invalid opcode: {opcode}')
    return error_num, error_msg[:-1].decode()  # Added decode()

################################################################
##
##            ERRORS AND EXCEPTIONS
##
################################################################

class TFTPValueError(ValueError):
    pass

class NetworkError(Exception):
    """
    Qualquer erro de rede, como "host não encontrado", tempos limite, etc.
    """

class ProtocolError(Exception):
    """Erro de protocolo TFTP, como opcode inesperado, número de bloco inválido, etc.
    """

class Err(Exception):
    """
    Um erro enviado pelo servidor. Pode ser causado porque uma leitura/gravação
    não pode ser processado. Erros de leitura e gravação durante a transmissão de arquivos
    também fazer com que essa mensagem seja enviada, e a transmissão é então
    Terminada. O número do erro fornece um código de erro numérico, seguido de
    por uma mensagem de erro ASCII que pode conter
    informações específicas do sistema.
    """
    def __init__(self, code, msg):  # Fixed __init__ method
        super().__init__(f"TFTP Error {code}: {msg}")  # Fixed super() call
        self.code = code
        self.msg = msg

#################################################################
##
##              COMMON UTILITIES
##              Mostly related to network tasks
##
#################################################################

def _make_is_valid_hostname():
    allowed = re.compile(r"(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    def _is_valid_hostname(hostname):
        """
        From: http://stackoverflow.com/questions/2532053/validate-a-hostname-string
        See also: https://en.wikipedia.org/wiki/Hostname (and the RFC 
        referenced there)
        """
        if not 0 < len(hostname) <= 255:
            return False
        if hostname[-1] == ".":
            #strip exactly one dor from the right, if present
            hostname = hostname[:-1]
        return all(allowed.match(x) for x in hostname.split("."))
    return _is_valid_hostname

_is_valid_hostname = _make_is_valid_hostname()

def get_host_info(server_addr: str) -> tuple[str, str]:
    """
    Retorna o ip do servidor e o nome do host para server_addr. Este parâmetro pode
    ou ser um endereço IP, caso em que esta função tenta consultar
    seu nome de host ou vice-versa.
    Essas funções gerarão uma exceção ValueError se o nome do host em
    server_addr está mal formado e gera NetworkError se não conseguirmos
    um endereço IP para esse nome de host.
    """
    try:
        ipaddress.ip_address(server_addr)
    except ValueError:
        try:
            server_addr = socket_mod.gethostbyname(server_addr)
        except socket_mod.gaierror:
            raise NetworkError(f"unknown server: {server_addr}.")

    try:
        server_name = socket_mod.gethostbyaddr(server_addr)[0]
    except socket_mod.herror:
        server_name = ""

    return server_addr, server_name

def is_ascii_printable(txt: str) -> bool:
    return set(txt).issubset(string.printable)
    # ALTERNATIVA: return not set(txt) - set(string.printable)