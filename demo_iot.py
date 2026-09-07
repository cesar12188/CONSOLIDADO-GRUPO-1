"""Demo IoT: float32 | nodo12 | control ASCII24 | paridad1."""

import struct

KEY = 0x55
PAYLOAD_BITS, FRAME_BITS, WIRE_BYTES = 68, 69, 9


def rol8(value):
    return ((value << 1) | (value >> 7)) & 0xFF


def ror8(value):
    return ((value >> 1) | (value << 7)) & 0xFF


def parity(value, width):
    result = 0
    for position in range(width):
        result ^= (value >> position) & 1
    return result


def encode(temperature, node, control):
    if type(node) is not int or not 0 <= node < (1 << 12):
        raise ValueError("El nodo debe estar entre 0 y 4095")
    raw_control = control.encode("ascii")
    if len(raw_control) != 3:
        raise ValueError("El control debe ocupar 3 bytes ASCII")
    temp_bits = int.from_bytes(struct.pack(">f", temperature), "big")
    obfuscated = bytes(rol8(byte) ^ KEY for byte in raw_control)
    payload = (temp_bits << 36) | (node << 24)
    payload |= int.from_bytes(obfuscated, "big")
    frame = (payload << 1) | parity(payload, PAYLOAD_BITS)
    return frame.to_bytes(WIRE_BYTES, "big")


def decode(packet):
    if len(packet) != WIRE_BYTES:
        raise ValueError("Se requieren 9 bytes")
    frame = int.from_bytes(packet, "big")
    if frame >> FRAME_BITS:
        raise ValueError("Los 3 bits de relleno deben ser cero")
    if parity(frame, FRAME_BITS):
        raise ValueError("Paridad incorrecta: error detectado")
    payload = frame >> 1
    temp_bits = (payload >> 36) & 0xFFFFFFFF
    node = (payload >> 24) & 0xFFF
    obfuscated = (payload & 0xFFFFFF).to_bytes(3, "big")
    control = bytes(ror8(byte ^ KEY) for byte in obfuscated)
    temperature = struct.unpack(">f", temp_bits.to_bytes(4, "big"))[0]
    return temperature, node, control.decode("ascii")


def rejects(operation):
    try:
        operation()
    except ValueError:
        return True
    return False


def main():
    packet = encode(98.6, 0xAF3, "LOG")
    frame = int.from_bytes(packet, "big")
    payload = frame >> 1
    temperature, node, control = decode(packet)

    assert packet.hex() == "0858a66675e79b97b6"
    assert (node, control) == (0xAF3, "LOG")
    assert abs(temperature - 98.6) < 0.00001
    assert all(ror8((rol8(b) ^ KEY) ^ KEY) == b for b in range(256))
    assert all(
        rejects(lambda n=n: encode(98.6, n, "LOG")) for n in (-1, 4096)
    )
    assert rejects(lambda: encode(98.6, node, "LONG"))
    assert rejects(lambda: encode(98.6, node, "L\u00d3G"))
    assert rejects(lambda: decode(packet[:-1]))
    assert rejects(lambda: decode(b"\x00" + packet))
    assert all(
        rejects(lambda f=frame ^ (1 << i): decode(f.to_bytes(9, "big")))
        for i in range(72)
    )

    print("Trama hexadecimal:", packet.hex(" ").upper())
    print("Trama binaria por bytes:", " ".join(f"{b:08b}" for b in packet))
    ones = sum((payload >> i) & 1 for i in range(PAYLOAD_BITS))
    print(f"Payload: {PAYLOAD_BITS} bits; unos: {ones}; paridad par: {frame & 1}")
    print(f"Recuperado: T={temperature:.17f}; nodo=0x{node:X}; control={control}")

    one_bit = (frame ^ (1 << 1)).to_bytes(9, "big")
    try:
        decode(one_bit)
    except ValueError as error:
        print("Un bit alterado, rechazado:", error)

    two_bits = (frame ^ (1 << 37) ^ (1 << 38)).to_bytes(9, "big")
    altered = decode(two_bits)
    assert altered[0] != temperature
    print(f"Dos bits alterados pasan paridad: T={altered[0]:.17f}")

    reference_data = struct.pack(">fH3s", 98.6, 0xAF3, b"LOG")
    reference_p = parity(int.from_bytes(reference_data, "big"), 72)
    reference = struct.pack(">fH3sB", 98.6, 0xAF3, b"LOG", reference_p)
    assert len(reference) == 10 and parity(int.from_bytes(reference, "big"), 80) == 0

    before, after = len(reference), len(packet)
    print(f"Referencia: {before} bytes; empaquetado: {after} bytes")
    print(f"Ahorro real: {100*(before-after)/before:.2f}%")
    print(f"Razón de tamaños (final/inicial): {100*after/before:.2f}%")
    print(f"Reducción lógica: {100*(80-FRAME_BITS)/80:.2f}% (69/80 bits)")
    print("Todas las pruebas pasaron.")


if __name__ == "__main__":
    main()