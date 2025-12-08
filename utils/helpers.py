

def bytes_to_hex_display(data: bytes, max_length: int = 32) -> str:

    hex_str = data.hex()
    if len(hex_str) > max_length * 2:
        return f"{hex_str[:max_length]}...({len(data)} bytes total)"
    return hex_str
