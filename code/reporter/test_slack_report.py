import slack_report, json


def test_no_results():
    header = "My Security Report"
    context = "Brought to you by Coffee"
    footer = "This goes at the bottom!"

    report = slack_report.SlackSecurityReport(threshold="0.8")
    report.header = header
    report.context = context
    report.footer = footer
    blocks = report.get_blocks()

    assert len(blocks) == 8

    # kev count is zero
    assert blocks[6].elements[0].elements[0].elements[1].text == "0"

    # epss count is zero
    assert blocks[6].elements[0].elements[0].elements[1].text == "0"

    report.add_sechub_issue("prod", "security issue!", "med")
    report.add_kev_occurence("cve-1234", 2)
    report.add_epss_occurence("cve-1234", 2)

    blocks = report.get_blocks()

    # 1 sechub issue present
    assert len(blocks[4].elements[0].elements) == 1

    # kev count is 1
    assert blocks[7].elements[0].elements[0].elements[1].text == "1"

    # epss count is 1
    assert blocks[7].elements[0].elements[0].elements[1].text == "1"


def test_get_payload():
    header = "My Security Report"
    context = "Brought to you by Coffee"
    footer = "This goes at the bottom!"

    report = slack_report.SlackSecurityReport(threshold="0.8")
    report.header = header
    report.context = context
    report.footer = footer

    payload = report.get_payload()["blocks"]
    json.dumps({"blocks": payload})
    