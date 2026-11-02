from analyzer import extract_ip, analyze_log

def test_extract_ip():
    line = "Failed password for admin from 192.0.2.10"

    result = extract_ip(line)
    assert result == "192.0.2.10"

def test_extarct_ip_no_ip():
    line = "Invalid login attempts"

    result = extract_ip(line)
    assert result is None 

def test_extract_ip_accepted_login():
    line = "Accepted password for admin from 192.0.2.20 port 22 ssh2"

    result =  extract_ip(line)

    assert result == "192.0.2.20"

def test_bruteforce_then_success(tmp_path):
    log_file = tmp_path / "test.log"
    log_file.write_text(
        "Failed password for admin from 192.0.2.10 port 22 ssh2\n" * 5
        + "Accepted password for admin from 192.0.2.10 port 22 ssh2\n"
    )

    counts, alerts = analyze_log(log_file)

    assert counts["192.0.2.10"] == 5
    assert ("192.0.2.10", 5) in alerts 

def test_brute_force_without_success(tmp_path):
    failed_log = tmp_path / "failed_log_file"
    failed_log.write_text(
        "Failed password for admin from 192.0.2.10 port 22 ssh2\n" * 5
        )
    failed_counts, alerts = analyze_log(failed_log)

    assert failed_counts["192.0.2.10"] == 5
    assert alerts == []

def test_below_threshold(tmp_path):
    failed_log = tmp_path / "failed_log_file"
    failed_log.write_text(
        "Failed password for admin from 192.0.2.10 port 22 ssh2\n" * 2
        )
    failed_counts, alerts = analyze_log(failed_log)

    assert failed_counts["192.0.2.10"] == 2
    assert alerts == []

def test_bruteforce_then_success(tmp_path):
    log = tmp_path / "auth.log"

    log.write_text(
        "Oct 12 10:15:01 server sshd[1]: Failed password for root from 192.0.2.10 port 22 ssh2\n"
        "Oct 12 10:15:10 server sshd[2]: Failed password for root from 192.0.2.10 port 22 ssh2\n"
        "Oct 12 10:15:20 server sshd[3]: Failed password for root from 192.0.2.10 port 22 ssh2\n"
        "Oct 12 10:15:30 server sshd[4]: Failed password for root from 192.0.2.10 port 22 ssh2\n"
        "Oct 12 10:15:40 server sshd[5]: Failed password for root from 192.0.2.10 port 22 ssh2\n"
        "Oct 12 10:15:50 server sshd[6]: Accepted password for root from 192.0.2.10 port 22 ssh2\n"
    )

    counts, alerts = analyze_log(log)

    assert counts["192.0.2.10"] == 5
    assert any(a[0] == "BRUTE FORCE" for a in alerts)
    assert any(a[0] == "SUCCESS AFTER FAILURES" for a in alerts)


def test_brute_force_within_5_minutes(tmp_path):
    log = tmp_path / "auth.log"

    log.write_text(
        "Oct 12 10:15:01 server sshd[1]: Failed password for root from 203.0.113.5 port 22 ssh2\n"
        "Oct 12 10:15:10 server sshd[2]: Failed password for root from 203.0.113.5 port 22 ssh2\n"
        "Oct 12 10:15:20 server sshd[3]: Failed password for root from 203.0.113.5 port 22 ssh2\n"
        "Oct 12 10:15:30 server sshd[4]: Failed password for root from 203.0.113.5 port 22 ssh2\n"
        "Oct 12 10:15:40 server sshd[5]: Failed password for root from 203.0.113.5 port 22 ssh2\n"
    )

    counts, alerts = analyze_log(log)

    assert counts["203.0.113.5"] == 5
    assert any(a[0] == "BRUTE FORCE" for a in alerts)
