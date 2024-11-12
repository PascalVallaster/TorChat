import hashlib
from socket import socket
import os
import sys

from asn1crypto.core import Sequence
from click import Tuple
import time

from EnDeCrypt import ECDH, Symmetrical
from OLD.EnDeCrypt_OLD import encryptStringSymmetrical


class InternalCodes:
    """
        Binary Codes for internal use with following format:

        0b 4 3 2 1 0

        0) unencrypted traffic  (0)     /   encrypted traffic (1)\n
        If set to 0, other flags are ignored.
        If 1, the data is at least encrypted once.

        1) no additional encryption layer (0)     /   additional encryption layer (1)\n
        Gives information about the number of encryption layers the data is encrypted with.
        If 0, data is encrypted just once.
        If 1, implies that first bit is also set to 1, else it will be ignored.
        If 1, data is encrypted with 2 layers of encryption.

        2) addressed to server  (0)     /   addressed to client     (1)

        3) continue connection  (0)     /   tear-down connection    (1)

        4) ----                 (0)     /   terminate everything    (1)\n
        If 1, implies tear-down connection is 1 regardless of actual status

        0/1) layers of encryption:
           0  ...  Received data has 0 layers of encryption
           1  ...  Received data has 1 layer of encryption
           11 ...  Received data has 2 layers of encryption
    """
    std_codesLen:   int = 2
    encrypted:      int = 0b1
    unencrypted:    int = 0b0
    zero_layer:     int = unencrypted
    one_layer:      int = encrypted
    two_layer:      int = 2 * encrypted
    addr_toServer:  int = 0b0
    addr_toClient:  int = 0b1
    cont_con:       int = 0b0
    tear_down:       int = 0b1


    def code_name(self, _code: int, _pos: int) -> str:
        pass


class Encryption(Symmetrical):
    # Class intern variables:
    # Length:
    sym_encr_inst: Symmetrical
    std_length_buffer: int = 1_000_000_000
    std_codes_length: int
    # ECDH:
    ecdh_instance_forServer: ECDH
    ecdh_instance_forClient: ECDH
    # Symmetrical Encr:

    # Shard (Public) variables
    aes_key_forServer: bytes
    aes_key_forClient: bytes

    codes = InternalCodes

    def __init__(self):
        self.ecdh_instance_forServer = ECDH()
        self.ecdh_instance_forClient = ECDH()

    def recv_length(self, client: socket, key) -> int:
        return int(
            self.decryptStringSymmetrical(
                client.recv(self.std_length_buffer),
                key
            )
        )

    def send_length(self, to_send, send_method: socket.send, key, flags:bool=True) -> None:
        to_send = to_send.encode() if type(to_send) == str else to_send
        send_method(
            self.encryptStringSymmetrical(
                str(len(to_send) + (self.codes.std_codesLen if flags else 0)).zfill(self.std_length_buffer),
                key
            )
        )

    def hash_key(self, key):
        return hashlib.sha512(key).hexdigest().encode()


class Connection(socket):
    codes: InternalCodes
    # Default bit codes
    default_secured:    int = 0b11
    default_addr:       int = 0b1
    default_term:       int = 0b0
    default_recv_flags: int = 0b10

    host_ip = "127.0.0.1"
    host_port = 5000
    base_encoding = "utf-8"

    internal_codes: int = 0b0  # Will get updated with used codes (-> for more consistence debugging)

    encryption_inst: Encryption

    def __init__(self):
        super().__init__()
        self.encryption_inst = Encryption()
        self.codes = InternalCodes()
        self.init_full_connection()

    def __enter__(self): super().__enter__()
    def __exit__(self, **args): self.tier_down_connection()

    def tier_down_connection(self):
        del self.encryption_inst.aes_key_forClient
        del self.encryption_inst.aes_key_forServer
        del self.encryption_inst.ecdh_instance_forClient.hex_derived_shared_secret_key
        del self.encryption_inst.ecdh_instance_forServer.hex_derived_shared_secret_key
        del self.encryption_inst.ecdh_instance_forClient.hex_public_key
        del self.encryption_inst.ecdh_instance_forServer.hex_public_key
        del self.encryption_inst.ecdh_instance_forClient
        del self.encryption_inst.ecdh_instance_forServer
        del self.encryption_inst
        self.close()

    def connect(self, address=(host_ip, host_port), /):
        super().connect(address)

    def send(self, data:bytes|str, flags:int=..., /):
        self.internal_codes = flags
        data = self.__encode(data)
        if not flags & 0b1:  # __traffic_encryption = 0b0 (unencrypted)
            super().send(data)
            return
        else:
            data = self.__convert_codes(flags) + data
            if not (flags >> 1) & 0b1:  # __addressed_to = 0b0 (addr_toServer)
                self.__send_to_server(data, flags)
            elif (flags >> 1) & 0b1:  # __addressed_to = 0b1 (addr_toClient)
                self.__send_to_client(data, flags)
            del data

    def recv(self, bufsize=..., flags=..., /) -> bytes:
        """
        Recv Flags:\n
        0 ... unencrypted
        1 ... encrypted by server
        10 ... encrypted by client
        """
        if flags == Ellipsis:  # That means nothing was passed as a value for flags
            flags = self.default_recv_flags  # Default means data is encrypted with 2 layers

        if not flags:  # Unencrypted / plain text
            return super().recv(bufsize)
        else:
            bufsize = self.encryption_inst.recv_length(self, self.encryption_inst.aes_key_forServer)
            data = super().recv(bufsize)
            if flags & 0b1:  # Encrypted with 1 layer
                data = self.__remove_encryption_layer(data, self.encryption_inst.aes_key_forServer)
                return data
            elif not flags & 0b1 and (flags >> 1) & 0b1:  # Encrypted with 2 layers
                data = self.__remove_encryption_layer(data, self.encryption_inst.aes_key_forServer)
                data = self.__remove_encryption_layer(data, self.encryption_inst.aes_key_forClient)
                return data

    def init_full_connection(self):
        # BEGIN Establishing encrypted connection
        # BEGIN Handshake with server
        # Generate DH Keys for server
        self.encryption_inst.ecdh_instance_forServer.generate_all_keys()

        # START Exchange DH keys
        self.send(
            self.encryption_inst.ecdh_instance_forServer.hex_public_key,
            self.__codes(__traffic_encryption=self.codes.zero_layer,
                         __addressed_to=self.codes.addr_toServer)
        )
        self.encryption_inst.ecdh_instance_forServer.process_recv_public_key(
            self.recv(
                self.encryption_inst.ecdh_instance_forServer.key_bit_length,
                self.codes.unencrypted
            )
        )
        self.encryption_inst.ecdh_instance_forServer.generate_shared_secret_key()
        self.encryption_inst.aes_key_forServer = self.encryption_inst.ecdh_instance_forServer.hex_derived_shared_secret_key
        # END Exchange DH keys
        # BEGIN Handshake Check --> '{codes}{hashed_aes_key}'
        data = self.encryption_inst.hash_key(self.encryption_inst.aes_key_forServer)
        self.send(data,
                  self.__codes(__addressed_to=self.codes.addr_toServer)
                  )  # Send encrypted hash of aes key and codes to server for confirmation
        if self.recv(self.codes.one_layer) == self.encryption_inst.hash_key(self.encryption_inst.aes_key_forServer):
            pass  # Encryption keys are equal, handshake was successful
        # END Handshake with server

        # BEGIN Key exchange with client
        # Generate DH Keys for client
        self.encryption_inst.ecdh_instance_forClient.generate_all_keys()

        # START Exchange DH Keys
        self.send(
            self.encryption_inst.ecdh_instance_forClient.hex_public_key,
            self.__codes(__traffic_encryption=self.codes.one_layer,
                         __addressed_to=self.codes.addr_toClient)
        )
        self.encryption_inst.ecdh_instance_forClient.process_recv_public_key(
            self.recv(
                # self.encryption_inst.ecdh_instance_forClient.key_bit_length,  # --> length of packet is recv by server
                self.codes.one_layer
            )
        )

        self.encryption_inst.ecdh_instance_forClient.generate_shared_secret_key()
        self.encryption_inst.aes_key_forClient = self.encryption_inst.ecdh_instance_forClient.hex_derived_shared_secret_key
        # END Exchange DH Keys
        # BEGIN Handshake Check --> '{codes}{hashed_aes_key}'
        data = self.encryption_inst.hash_key(self.encryption_inst.aes_key_forClient)
        self.send(data, self.__codes())  # Send encrypted hash of aes key and codes to server for confirmation
        if self.recv() == self.encryption_inst.hash_key(self.encryption_inst.aes_key_forClient):
            pass  # Encryption keys are equal, handshake was successful
        # END Handshake with client
        # END Establishing encrypted connection

    def __send_to_server(self, __data: bytes, __flags: int):
        __data = self.__convert_codes(__flags) + __data
        __data_encr = self.encryption_inst.encryptStringSymmetrical(__data, self.encryption_inst.aes_key_forServer)
        self.encryption_inst.send_length(__data_encr, super().send, self.encryption_inst.aes_key_forServer)
        self.send(__data_encr)

    def __send_to_client(self, __data: bytes, __flags: int):
        __data = self.__convert_codes(__flags) + __data
        __data_encr = self.encryption_inst.encryptStringSymmetrical(__data, self.encryption_inst.aes_key_forClient)
        __data_encr_encr = self.encryption_inst.encryptStringSymmetrical(
            self.__convert_codes(__flags) + __data_encr, self.encryption_inst.aes_key_forServer
        )
        self.encryption_inst.send_length(__data_encr_encr, super().send, self.encryption_inst.aes_key_forServer)
        self.send(__data_encr_encr)

    def __encode(self, _text) -> bytes: return _text.encode(self.base_encoding) if type(_text) == str else _text
    def __convert_codes(self, __codes: int) -> bytes: return str(__codes).encode(self.base_encoding).zfill(4)

    def __codes(self, __traffic_encryption=default_secured,
                __addressed_to=default_addr,
                __terminate_connection=default_term) -> int:
        return (__terminate_connection << 3) | (__addressed_to << 2) | __traffic_encryption
        # return (__terminate_connection << 2) | (__addressed_to << 1) | __traffic_encryption

    def __codes_interpreter(self, __codes) -> tuple:
        bool_tuple: tuple = ()
        # Encryption / Layers
        if __codes & 0b1:
            if (__codes >> 1) & 0b1:
                bool_tuple += (True,True)
                __codes = __codes >> 2
            else:
                bool_tuple += (True,False)
                __codes = __codes >> 1
        else:
            bool_tuple += (False,False)
            __codes = __codes >> 1

        # Addressed to...
        if __codes & 0b1: bool_tuple += (True,)
        else: bool_tuple += (False,)

        # Connection status
        if (__codes >> 1) & 0b1: bool_tuple += (True,)
        else: bool_tuple += (False,)

        return bool_tuple

    def __add_encryption_layer(self, __data, __key) -> bytes: return self.encryption_inst.encryptStringSymmetrical(__data, __key)
    def __remove_encryption_layer(self, __data, __key) -> bytes: return self.encryption_inst.decryptStringSymmetrical(__data, __key)


class SimpleTerminalChat:
    connection: Connection

    def __init__(self):
        self.connection = Connection()

    def test(self):  # For beginning / debugging purposes
        print(f"Sending test message at {time.time()}...")
        self.connection.send(f"Hi at {time.time()}")
        print(f"Waiting for response at {time.time()}...")
        data = self.connection.recv()
        print(f"Received response at {time.time()}!:\n{data}")
        print(f"Sending connection tier-down signal at {time.time()}...")
        self.connection.tier_down_connection()
        print(f"Connection was ended successfully at {time.time()}! Congrats!")
        exit("Exiting...")

    def run(self):
        self.test()


class PagerChat:
    # Idea: have a pager like chat in the terminal, or gui like application
    # To be coded soon...
    pass




if __name__ == '__main__':
    simpleChat = SimpleTerminalChat()
    simpleChat.run()



