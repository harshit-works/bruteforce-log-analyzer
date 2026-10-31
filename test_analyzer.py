from analyzer import extract_ip

def test_extract_ip():
    line = "Failed password for admin from 192.0.2.10"

    result = extract_ip(line)
    assert result == "192.0.2.10"