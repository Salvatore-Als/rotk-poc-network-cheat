"""
soe_reassembly.py — RC4 + réassemblage de fragments SOE.

Port Python de https://github.com/H1emu/h1z1-server
(soeinputstream.ts + RC4 de h1emu-core).

Clé RC4 par défaut (src/utils/constants.ts) :
    DEFAULT_CRYPTO_KEY = "F70IaxuU8C/w7FPXY1ibXw=="
"""

import base64

DEFAULT_CRYPTO_KEY_B64 = "F70IaxuU8C/w7FPXY1ibXw=="
DEFAULT_CRYPTO_KEY = base64.b64decode(DEFAULT_CRYPTO_KEY_B64)

MAX_UINT8 = 0xFF
MAX_UINT16 = 0xFFFF
MAX_SEQUENCE = MAX_UINT16
DATA_HEADER_SIZE = 4

# Opcodes position broadcast : 0x78 (client 2015), 0x79 (client 2016 / ROTK).
POSITION_BROADCAST_OPCODES = {0x78, 0x79}


class RC4:
    """RC4 avec état persistant — une instance par connexion, pas de reinit entre les paquets."""

    def __init__(self, key: bytes):
        S = list(range(256))
        j = 0

        for i in range(256):
            j = (j + S[i] + key[i % len(key)]) % 256
            S[i], S[j] = S[j], S[i]

        self.S = S
        self.i = 0
        self.j = 0

    def crypt(self, data: bytes) -> bytes:
        S = self.S
        i, j = self.i, self.j
        out = bytearray(len(data))

        for idx, byte in enumerate(data):
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            out[idx] = byte ^ S[(S[i] + S[j]) % 256]

        self.i, self.j = i, j
        return bytes(out)


def _wrap_u16(value: int) -> int:
    if value > MAX_UINT16:
        value -= MAX_UINT16 + 1
    return value


def _read_data_length(data: bytes, offset: int):
    """Longueur encodée en 1, 3 ou 7 octets selon la valeur (protocole SOE)."""
    length = data[offset]

    if length == MAX_UINT8:
        if data[offset + 1] == MAX_UINT8 and data[offset + 2] == MAX_UINT8:
            length = int.from_bytes(data[offset + 3:offset + 7], "big")
            size_value_bytes = 7
        else:
            length = int.from_bytes(data[offset + 1:offset + 3], "big")
            size_value_bytes = 3
    else:
        size_value_bytes = 1

    return length, size_value_bytes


def _parse_channel_packet_data(data: bytes) -> list[bytes]:
    """Découpe un message réassemblé en sous-messages (header 0x00 0x19)."""
    if len(data) >= 2 and data[0] == 0x00 and data[1] == 0x19:
        app_data = []
        offset = 2

        while offset < len(data):
            length, size_value_bytes = _read_data_length(data, offset)
            offset += size_value_bytes
            app_data.append(data[offset:offset + length])
            offset += length

        return app_data

    return [data]


class SOEInputStream:
    """Port de SOEInputStream (soeinputstream.ts).

    Reçoit les corps Data/DataFragment (sans opcode/seq/CRC) dans l'ordre réseau,
    réassemble les fragments, déchiffre RC4, et appelle on_appdata() par message complet.
    on_error() est appelé sur incohérence de réassemblage (typiquement une perte de paquet).
    """

    def __init__(self, crypto_key: bytes, on_appdata, on_error=None, on_out_of_order=None):
        self._next_sequence = 0
        self._last_ack = -1
        self._app_data_map: dict[int, tuple[bytes, bool]] = {}
        self._use_encryption = False
        self._last_processed_sequence = -1
        self._rc4 = RC4(crypto_key)

        self._has_cpf = False
        self._cpf_total_size = -1
        self._cpf_data_size = -1
        self._cpf_data = bytearray()
        self._cpf_processed_sequences: list[int] = []

        self._on_appdata = on_appdata
        self._on_error = on_error or (lambda msg: None)
        self._on_out_of_order = on_out_of_order or (lambda seq: None)

    def set_encryption(self, value: bool):
        self._use_encryption = value

    def _process_single_data(self, sequence: int) -> list[bytes]:
        payload, _ = self._app_data_map.pop(sequence)
        self._last_processed_sequence = sequence
        return _parse_channel_packet_data(payload)

    def _process_fragmented_data(self, first_packet_sequence: int) -> list[bytes]:
        if not self._has_cpf:
            first_payload, _ = self._app_data_map[first_packet_sequence]
            self._cpf_total_size = int.from_bytes(first_payload[0:4], "big")
            self._cpf_data_size = 0
            self._cpf_data = bytearray(self._cpf_total_size)
            self._cpf_processed_sequences = []
            self._has_cpf = True

        i = len(self._cpf_processed_sequences)

        while i < len(self._app_data_map):
            fragment_sequence = (first_packet_sequence + i) % MAX_SEQUENCE
            fragment = self._app_data_map.get(fragment_sequence)

            if fragment is None:
                return []

            fragment_payload, _ = fragment
            is_first_packet = fragment_sequence == first_packet_sequence
            self._cpf_processed_sequences.append(fragment_sequence)

            # Le premier fragment a un header 4 octets (taille totale) à sauter.
            if is_first_packet:
                chunk = fragment_payload[DATA_HEADER_SIZE:]
            else:
                chunk = fragment_payload

            end = self._cpf_data_size + len(chunk)
            self._cpf_data[self._cpf_data_size:end] = chunk
            self._cpf_data_size = end

            if self._cpf_data_size > self._cpf_total_size:
                self._on_error(
                    f"processDataFragments: offset > totalSize: {self._cpf_data_size} > "
                    f"{self._cpf_total_size} (sequence {fragment_sequence}) "
                    f"(fragment length {len(fragment_payload)})"
                )

            if self._cpf_data_size == self._cpf_total_size:
                for seq in self._cpf_processed_sequences:
                    self._app_data_map.pop(seq, None)

                self._last_processed_sequence = fragment_sequence
                self._has_cpf = False
                return _parse_channel_packet_data(bytes(self._cpf_data))

            i += 1

        return []

    def _process_data(self):
        next_fragment_sequence = (self._last_processed_sequence + 1) & MAX_SEQUENCE
        entry = self._app_data_map.get(next_fragment_sequence)

        if entry is None:
            return

        _, is_fragment = entry

        if is_fragment:
            app_data = self._process_fragmented_data(next_fragment_sequence)
        else:
            app_data = self._process_single_data(next_fragment_sequence)

        if app_data:
            self._process_app_data(app_data)
            self._process_data()

    def _process_app_data(self, app_data: list[bytes]):
        for data in app_data:
            if self._use_encryption:
                # SOE : si les 2 premiers octets sont 0x00 0x00, on saute le premier avant RC4.
                if len(data) > 1 and data[0] == 0 and data[1] == 0:
                    data = self._rc4.crypt(data[1:])
                else:
                    data = self._rc4.crypt(data)

            self._on_appdata(data)

    def _acknowledge_input_data(self, sequence: int) -> bool:
        if sequence > self._next_sequence:
            self._on_out_of_order(sequence)
            return False

        ack = sequence

        for i in range(1, MAX_SEQUENCE):
            fragment_index = (self._last_ack + i) & MAX_SEQUENCE
            if fragment_index in self._app_data_map:
                ack = fragment_index
            else:
                break

        self._last_ack = _wrap_u16(ack)
        return True

    def write(self, data: bytes, sequence: int, is_fragment: bool):
        if sequence >= self._next_sequence:
            self._app_data_map[sequence] = (data, is_fragment)
            was_in_order = self._acknowledge_input_data(sequence)

            if was_in_order:
                self._next_sequence = _wrap_u16(self._last_ack + 1)
                self._process_data()
