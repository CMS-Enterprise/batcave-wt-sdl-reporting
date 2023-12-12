import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as lambda from 'aws-cdk-lib/aws-lambda'
import * as iam from "aws-cdk-lib/aws-iam"
import * as events from "aws-cdk-lib/aws-events"
import * as targets from "aws-cdk-lib/aws-events-targets"
import * as secretsManager from "aws-cdk-lib/aws-secretsmanager"
import * as assets from "aws-cdk-lib/aws-ecr-assets"


export class CdkStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    const snowflakeCreds = new secretsManager.Secret(this, "WatchtowerSnowflakeCredentials", {
      description:"Snowflake Service Account credentials for BatCAVE Watchtower Sechub/Nessus reporting automation"
    })
    const slackWebhook = new secretsManager.Secret(this, "WatchtowerSlackWebhook", {
      description: "Slack Webhook for #batcave-security-alerts"
    })
    
    const cmsPermissionsBoundary = iam.ManagedPolicy.fromManagedPolicyName(this, 'cmsPermissionsBoundary', 'cms-cloud-admin/developer-boundary-policy')
    iam.PermissionsBoundary.of(this).apply(cmsPermissionsBoundary)

    const reportingLambdaRole = new iam.Role(this, 'ReportingLambdaRole', {
      path: '/delegatedadmin/developer/',
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com')
    })

    const reportingLambda = new lambda.DockerImageFunction(this, "ReportingLambda", {
      code: lambda.DockerImageCode.fromImageAsset('code/reporter', {
        platform: assets.Platform.LINUX_ARM64
      }),
      role: reportingLambdaRole,
      architecture: lambda.Architecture.ARM_64,
      memorySize: 1024,
      timeout: cdk.Duration.minutes(1),
      environment: {
        'EPSS_THRESHOLD': '0.8',
        'SNOWFLAKE_SECRET_ARN': snowflakeCreds.secretArn,
        'SLACK_WEBHOOK_ARN': slackWebhook.secretArn,
        'SNOWFLAKE_DB': 'BUS_BATCAVE_SECURITY_DB',
        'SNOWFLAKE_WAREHOUSE': 'BATCAVESECURITY_WH',
        'SNOWFLAKE_ROLE': 'SVC_BATCAVESECURITY_ROLE',
        'SNOWFLAKE_SCHEMA': 'PUBLIC'
      }
    })

    const secretsManagerAccessPolicy = new iam.ManagedPolicy(this, 'secretsManagerAccess', {
      path: '/delegatedadmin/developer/',
      document: new iam.PolicyDocument({
        statements:[
          new iam.PolicyStatement({
            effect: iam.Effect.ALLOW,
            actions: ['secretsmanager:GetSecretValue'],
            resources: [
              slackWebhook.secretArn,
              snowflakeCreds.secretArn
            ]
          })
        ]
      })
    })
    
    reportingLambda.role?.addManagedPolicy(secretsManagerAccessPolicy)
    const lambda_cron = new events.Rule( this, 'reportingCron', {
      schedule: cdk.aws_events.Schedule.cron({minute: '0', hour: '14'})
    }
    )

    lambda_cron.addTarget(new targets.LambdaFunction(reportingLambda))
  }
}
