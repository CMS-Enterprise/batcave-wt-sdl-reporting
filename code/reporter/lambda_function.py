import boto3, os, json
import pandas as pd
import snowflake.connector
import slack_block
from datetime import date
from slack_sdk.webhook import WebhookClient


def get_epss_df():
    today = date.today()
    d1 = today.strftime("%Y-%m-%d")

    return pd.read_csv(
        f"https://epss.cyentia.com/epss_scores-{d1}.csv.gz",
        compression="gzip",
        header=1,
    )


def get_kev_df():
    return pd.read_csv(
        "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"
    )


def get_snowflake_connection(
    user: str,
    password: str,
    account: str,
    database: str,
    warehouse: str,
    role: str,
    schema: str,
    authenticator="snowflake",
    autocommit=True,
    login_timeout=60,
    network_timeout=30,
    socket_timeout=15,
):
    return snowflake.connector.connect(
        user=user,
        password=password,
        account=account,
        database=database,
        warehouse=warehouse,
        role=role,
        schema=schema,
        authenticator=authenticator,
        autocommit=autocommit,
        login_timeout=login_timeout,
        network_timeout=network_timeout,
        socket_timeout=socket_timeout,
    )


def get_nessus_vulns(snowflake_cur, kev_df, epss_df):
    """queries snowflake for nessus findings, flattens the table to be one row per CVE
    and intersects them with both the kev and epss dataframes
    """
    snowflake_cur.execute(
        "select ACCOUNTID, INSTANCEID, CVE, report_date from SEC_VW_VULN_AWS_BATCAVE WHERE report_date >current_date-2"
    )
    df = snowflake_cur.fetch_pandas_all()
    df["CVE"] = df["CVE"].apply(lambda x: json.loads(x))
    df = df.explode("CVE", ignore_index=True)
    df = df.dropna()
    df = pd.merge(df, epss_df, left_on="CVE", right_on="cve")
    df["isKEV"] = df.CVE.isin(kev_df.cveID).astype(bool)

    return df


# Base Numbers across environments
# Are there any KEVs in our environments
# Are there any vulns above a particular EPSS score in our environments
# New SecurityHub issues in the last 24 hours
# Rundown of securityhub issue types


def get_sechub_findings_past_24_hours(snowflake_cur):
    snowflake_cur.execute(
        "select TITLE, AWS_ACCOUNT_NAME, FINDINGPROVIDERFIELDS_SEVERITY_LABEL from BUS_BATCAVE_SECURITY_DB.PUBLIC.SEC_VW_COMMERCIAL_SECHUB_FINDINGS_BY_BATCAVE_ACCOUNT_ID WHERE RECORDSTATE='ACTIVE' and WORKFLOW_STATUS='NEW' and PRODUCTNAME not in ('Default', 'Inspector','GuardDuty') and CREATEDAT >= CURRENT_TIMESTAMP() - INTERVAL '24 hours'"
    )
    df = snowflake_cur.fetch_pandas_all()

    return df


def handler(event, context):
    snowflake_secret_arn = os.environ.get("SNOWFLAKE_SECRET_ARN")
    slack_webhook_arn = os.environ.get("SLACK_WEBHOOK_ARN")

    snowflake_warehouse = os.environ.get("SNOWFLAKE_WAREHOUSE")
    snowflake_database = os.environ.get("SNOWFLAKE_DB")
    snowflake_role = os.environ.get("SNOWFLAKE_ROLE")
    snowflake_schema = os.environ.get("SNOWFLAKE_SCHEMA")

    epss_threshold = float(os.environ.get("EPSS_THRESHOLD"))

    sm = boto3.client("secretsmanager")

    snowflake_secret = json.loads(
        sm.get_secret_value(SecretId=snowflake_secret_arn)["SecretString"]
    )
    slack_webhook = sm.get_secret_value(SecretId=slack_webhook_arn)["SecretString"]

    snowflake_con = get_snowflake_connection(
        user=snowflake_secret["SNOWFLAKE_USER"],
        password=snowflake_secret["SNOWFLAKE_PASS"],
        account=snowflake_secret["SNOWFLAKE_ACCOUNT_ID"],
        database=snowflake_database,
        warehouse=snowflake_warehouse,
        role=snowflake_role,
        schema=snowflake_schema,
    )

    snow_cur = snowflake_con.cursor()

    sechub_last_24 = get_sechub_findings_past_24_hours(snow_cur)

    nessus_vulns = get_nessus_vulns(snow_cur)

    epss_vulns = nessus_vulns[nessus_vulns["epss"] >= epss_threshold]
    kev_vulns = nessus_vulns[nessus_vulns["isKEV"] == True]
    kev_by_account = kev_vulns

    slack_report = slack_block.BatCAVEVulnReport()

    slack_report.set_epss_threshold(str(epss_threshold))
    slack_report.set_epss_count(epss_vulns["CVE"].count())
    slack_report.set_cisa_kev_count(kev_vulns["CVE"].count())

    epss_cve_by_env = (
        epss_vulns[["ACCOUNTID", "CVE"]]
        .groupby("CVE")["ACCOUNTID"]
        .nunique()
        .reset_index()
    )
    kev_cve_by_env = (
        kev_vulns[["ACCOUNTID", "CVE"]]
        .groupby("CVE")["ACCOUNTID"]
        .nunique()
        .reset_index()
    )

    for row in epss_cve_by_env.iterrows():
        cve_id = row[1][0]
        count = row[1][1]

        slack_report.add_epss_vuln(cve_id, count)

    for row in kev_cve_by_env.iterrows():
        cve_id = row[1][0]
        count = row[1][1]

        slack_report.add_kev_vuln(cve_id, count)

    for row in sechub_last_24.iterrows():
        issue_name = row[1][0]
        acct_name = row[1][1]

        slack_report.add_sechub_issue(acct_name, issue_name=issue_name)

    webhook_client = WebhookClient(slack_webhook)

    webhook_client.send(blocks=slack_report.get_blocks())
