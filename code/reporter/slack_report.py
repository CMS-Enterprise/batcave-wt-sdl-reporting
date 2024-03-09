from slackblocks import (
    Text,
    HeaderBlock,
    ContextBlock,
    DividerBlock,
    SectionBlock,
    RichTextBlock,
    RichTextLink,
    Message,
)
from slackblocks.rich_text import RichTextSection, RichTextList, ListType, RichText

from dataclasses import dataclass


@dataclass
class SecHubIssue:
    env_name: str
    name: str
    severity: str


@dataclass
class VulnOccurence:
    cve: str
    num_env: int


class SlackSecurityReport:
    def __init__(self, threshold: str):
        self.blocks = []
        self.header = None
        self.context = None
        self.epss_threshold = threshold
        self.sechub_issues = []
        self.epss_cves = []
        self.kev_cves = []

    def __form_blocks(self):
        self.blocks = []
        self.blocks.append(HeaderBlock(self.header))
        self.blocks.append(ContextBlock(elements=[Text(self.context)]))
        self.blocks.append(DividerBlock())
        self.blocks.append(SectionBlock("SecurityHub New Issues in the last 24 hours:"))
        if len(self.sechub_issues) > 0:
            self.blocks.append(
                RichTextBlock(
                    elements=[
                        RichTextList(
                            style=ListType.BULLET,
                            elements=[
                                RichTextSection(
                                    elements=[
                                        RichText(text=f"{x.env_name}: ", bold=True),
                                        RichText(text=x.name),
                                    ]
                                )
                                for x in self.sechub_issues
                            ],
                        )
                    ]
                )
            )
        self.blocks.append(DividerBlock())
        self.blocks.append(SectionBlock("*BatCAVE Infra Vulnerabilities via Nessus:*"))

        kev_vuln_block = RichTextBlock(
            elements=[
                RichTextList(
                    style=ListType.BULLET,
                    indent=1,
                    elements=[
                        RichTextSection(
                            elements=[
                                RichText(text="CISA KEV Vulns: ", bold=True),
                                RichText(text=f"{str(len(self.kev_cves))}"),
                            ]
                        )
                    ],
                )
            ]
        )
        if len(self.kev_cves) > 0:
            kev_vuln_block.elements.append(
                RichTextList(
                    style=ListType.BULLET,
                    indent=1,
                    elements=[
                        RichTextSection(
                            elements=[
                                RichTextLink(
                                    text=f"{x.cve}",
                                    url=f"https://www.cvedetails.com/cve/{x.cve}"
                                ),
                                RichText(
                                    text=f" present across {str(x.num_env)} AWS Accounts"
                                )
                            ]
                        )
                        for x in self.kev_cves
                    ],
                )
            )
        self.blocks.append(kev_vuln_block)

        epss_vuln_block = RichTextBlock(
            elements=[
                RichTextList(
                    style=ListType.BULLET,
                    elements=[
                        RichTextSection(
                            elements=[
                                RichText(
                                    text=f"Vulnerabilities above a {self.epss_threshold} EPSS score: ",
                                    bold=True,
                                ),
                                RichText(text=f"{str(len(self.epss_cves))}"),
                            ]
                        )
                    ],
                )
            ]
        )

        if len(self.epss_cves) > 0:
            epss_vuln_block.elements.append(
                RichTextList(
                    style=ListType.BULLET,
                    indent=1,
                    elements=[
                        RichTextSection(
                            elements=[
                                RichTextLink(
                                    text=f"{x.cve}",
                                    url=f"https://www.cvedetails.com/cve/{x.cve}"
                                ),
                                RichText(
                                    text=f" present across {str(x.num_env)} AWS Accounts"
                                )
                            ]
                        )
                        for x in self.epss_cves
                    ],
                )
            )
        self.blocks.append(epss_vuln_block)

    def get_blocks(self):
        self.__form_blocks()
        return self.blocks

    def get_payload(self):
        return Message(channel="None", blocks=self.get_blocks())

    def add_sechub_issue(self, env_name: str, issue_name: str, severity=None):
        self.sechub_issues.append(
            SecHubIssue(env_name=env_name, name=issue_name, severity=severity)
        )

    def add_kev_occurence(self, cve_id: str, num_accounts: int):
        self.kev_cves.append(VulnOccurence(cve=cve_id, num_env=num_accounts))

    def add_epss_occurence(self, cve_id: str, num_accounts: int):
        self.epss_cves.append(VulnOccurence(cve=cve_id, num_env=num_accounts))
