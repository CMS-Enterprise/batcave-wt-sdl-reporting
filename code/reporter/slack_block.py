import json


class BatCAVEVulnReport:
    def __init__(self):
        self.base = report_base_blocks

    def add_sechub_issue(self, env_name: str, issue_name: str) -> None:
        sechub_issue_block = {
            "type": "rich_text_section",
            "elements": [
                {"type": "text", "text": f"{env_name}: ", "style": {"bold": True}},
                {"type": "text", "text": f"{issue_name}"},
            ],
        }

        self.base["blocks"][4]["elements"][0]["elements"].append(sechub_issue_block)

    def set_cisa_kev_count(self, count: int) -> None:
        self.base["blocks"][7]["elements"][0]["elements"][0]["elements"][1][
            "text"
        ] = str(count)

    def add_kev_vuln(self, cve_id: str, env_count: str):
        self.base["blocks"][7]["elements"].insert(1,
            {
                "type": "rich_text_list",
                "style": "bullet",
                "indent": 1,
                "border": 0,
                "elements": [
                    {
                        "type": "rich_text_section",
                        "elements": [
                            {
                                "type": "text",
                                "text": f"{cve_id} present across {str(env_count)} AWS Accounts",
                            }
                        ],
                    }
                ],
            }
        )

    def set_epss_count(self, count: int) -> None:
        self.base["blocks"][7]["elements"][1]["elements"][0]["elements"][1][
            "text"
        ] = str(count)

    def add_epss_vuln(self, cve_id: str, env_count: str):
        self.base["blocks"][7]["elements"].insert(2,
            {
                "type": "rich_text_list",
                "style": "bullet",
                "indent": 1,
                "border": 0,
                "elements": [
                    {
                        "type": "rich_text_section",
                        "elements": [
                            {
                                "type": "text",
                                "text": f"{cve_id} present across {str(env_count)} AWS Accounts",
                            }
                        ],
                    }
                ],
            }
        )

    def set_epss_threshold(self, threshold: str) -> None:
        epss_str = f"Vulnerabilities above a {threshold} EPSS score: "

        self.base["blocks"][7]["elements"][1]["elements"][0]["elements"][0][
            "text"
        ] = epss_str

    def get_blocks(self):
        return self.base["blocks"]

    def build_payload(self) -> dict:
        return json.dumps(self.base)


report_base_blocks = {
    "blocks": [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": "BatCAVE SecHub and Nessus Daily Report",
                "emoji": True,
            },
        },
        {
            "type": "context",
            "elements": [
                {
                    "type": "plain_text",
                    "text": "Powered by BatCAVE Watchtower and CMS Security Data Lake!",
                    "emoji": True,
                }
            ],
        },
        {"type": "divider"},
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*SecurityHub New Issues in last 24 hours:*",
            },
        },
        {
            "type": "rich_text",
            "elements": [{"type": "rich_text_list", "style": "bullet", "elements": []}],
        },
        {"type": "divider"},
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*BatCAVE Infra Vulnerabilites via Nessus:*",
            },
        },
        {
            "type": "rich_text",
            "elements": [
                {
                    "type": "rich_text_list",
                    "style": "bullet",
                    "elements": [
                        {
                            "type": "rich_text_section",
                            "elements": [
                                {
                                    "type": "text",
                                    "text": "CISA KEV Vulns: ",
                                    "style": {"bold": True},
                                },
                                {"type": "text", "text": "0"},
                            ],
                        }
                    ],
                },
                {
                    "type": "rich_text_list",
                    "style": "bullet",
                    "elements": [
                        {
                            "type": "rich_text_section",
                            "elements": [
                                {
                                    "type": "text",
                                    "text": "Vulnerabilities above a .8 EPSS score: ",
                                    "style": {"bold": True},
                                },
                                {"type": "text", "text": "0"},
                            ],
                        }
                    ],
                },
            ],
        },
    ]
}
