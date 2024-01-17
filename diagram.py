from diagrams import Cluster, Diagram, Edge
from diagrams.aws.compute import Lambda
from diagrams.aws.security import SecretsManager
from diagrams.aws.management import CloudwatchEventTimeBased
from diagrams.saas.analytics import Snowflake
from diagrams.saas.chat import Slack

graph_attr = {"fontsize": "25", "center": "true"}

with Diagram("BatCAVE SDL Reporting Automation", direction="TB", graph_attr=graph_attr):
    with Cluster("AWS"):
        cron = CloudwatchEventTimeBased("Cron - Daily")
        lambda_func = Lambda("BatCAVE SDL Lambda")
        with Cluster("Secrets"):
            slack_secret = SecretsManager("Slack Webhook")
            snowflake_secret = SecretsManager("Snowflake Creds")

        cron >> lambda_func
        (
            lambda_func
            >> Edge(label="GetSecretValue", color="red", style="bold")
            >> slack_secret
        )

        lambda_func >> Edge(label="GetSecretValue", color="red") >> snowflake_secret

    snowflake = Snowflake("Security Data Lake")
    slack = Slack("Slack")

    lambda_func >> Edge(label="Execute Queries", color="green") >> snowflake

    lambda_func >> Edge(label="POST report to webhook", color="green") >> slack
