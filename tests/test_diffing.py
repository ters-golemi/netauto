from netauto import diffing


def test_identical_configs_produce_no_diff():
    cfg = "hostname a\ninterface Gi0/1\n description uplink\n"
    assert diffing.unified(cfg, cfg, family="cisco") == ""


def test_volatile_lines_are_ignored():
    a = "Building configuration...\nCurrent configuration : 1234 bytes\nhostname a\n"
    b = "Building configuration...\nCurrent configuration : 9999 bytes\nhostname a\n"
    assert diffing.unified(a, b, family="cisco") == ""


def test_secrets_are_masked_not_compared():
    a = "enable secret 9 $9$aaaa\nhostname a\n"
    b = "enable secret 9 $9$bbbb\nhostname a\n"
    assert diffing.unified(a, b, family="cisco") == ""


def test_real_change_is_reported():
    a = "hostname a\nip http server\n"
    b = "hostname a\nno ip http server\n"
    diff = diffing.unified(a, b, family="cisco")
    assert "ip http server" in diff
    assert diffing.summarize(diff)["changed"] >= 2
