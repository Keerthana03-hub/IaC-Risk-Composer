"""
tests/test_cloudformation_parser.py
-----------------------------------
Stage 3: Comprehensive test suite for AWS CloudFormation parser, intrinsic functions,
safe format detection, and integration with the analysis API.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Ensure backend root is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from fastapi.testclient import TestClient

from main import app
from services.cloudformation_parser import CloudFormationParser
from services.infrastructure_schema import IaCFormat, NormalizedInfrastructure, ParsingStatus
from services.parser_registry import (
    MalformedIaCError,
    UnsupportedFormatError,
    default_parser_registry,
    identify_iac_format,
    parse_iac,
)

client = TestClient(app)


# ---------------------------------------------------------------------------
# Test Fixtures & Sample Templates
# ---------------------------------------------------------------------------

SAMPLE_CFN_YAML = """
AWSTemplateFormatVersion: '2010-09-09'
Description: Production S3 Storage Tier
Resources:
  SecureVaultBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: corp-secure-vault-2026
      AccessControl: Private
"""

SAMPLE_CFN_JSON = json.dumps({
    "AWSTemplateFormatVersion": "2010-09-09",
    "Description": "Compute Instance Template",
    "Resources": {
        "ComputeNode": {
            "Type": "AWS::EC2::Instance",
            "Properties": {
                "ImageId": "ami-0123456789abcdef0",
                "InstanceType": "t3.medium"
            }
        }
    }
})


# ---------------------------------------------------------------------------
# 1. Valid CloudFormation YAML
# ---------------------------------------------------------------------------


def test_1_valid_cloudformation_yaml():
    parser = CloudFormationParser()
    infra = parser.parse(SAMPLE_CFN_YAML, filename="storage.yaml")

    assert isinstance(infra, NormalizedInfrastructure)
    assert infra.source_format == IaCFormat.CLOUDFORMATION.value
    assert infra.source_file == "storage.yaml"
    assert infra.resource_count == 1
    assert infra.resource_types == ["AWS::S3::Bucket"]
    assert infra.parsing_status == ParsingStatus.VALID.value

    bucket = infra.get_resource("AWS::S3::Bucket.SecureVaultBucket")
    assert bucket is not None
    assert bucket.name == "SecureVaultBucket"
    assert bucket.type == "AWS::S3::Bucket"
    assert bucket.provider == "aws"
    assert bucket.attributes["BucketName"] == "corp-secure-vault-2026"
    assert bucket.attributes["AccessControl"] == "Private"


# ---------------------------------------------------------------------------
# 2. Valid CloudFormation JSON
# ---------------------------------------------------------------------------


def test_2_valid_cloudformation_json():
    parser = CloudFormationParser()
    infra = parser.parse(SAMPLE_CFN_JSON, filename="compute.json")

    assert isinstance(infra, NormalizedInfrastructure)
    assert infra.source_format == IaCFormat.CLOUDFORMATION.value
    assert infra.resource_count == 1
    instance = infra.get_resource("AWS::EC2::Instance.ComputeNode")
    assert instance is not None
    assert instance.type == "AWS::EC2::Instance"
    assert instance.attributes["InstanceType"] == "t3.medium"


# ---------------------------------------------------------------------------
# 3. Multiple Resources
# ---------------------------------------------------------------------------


def test_3_multiple_resources():
    multi_yaml = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  DataBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: data-bucket
  AppSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Application firewall
  WebServer:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: ami-11111111
"""
    parser = CloudFormationParser()
    infra = parser.parse(multi_yaml, filename="multi.yml")

    assert infra.resource_count == 3
    assert set(infra.resource_types) == {"AWS::EC2::Instance", "AWS::EC2::SecurityGroup", "AWS::S3::Bucket"}
    assert infra.get_resource("AWS::S3::Bucket.DataBucket") is not None
    assert infra.get_resource("AWS::EC2::SecurityGroup.AppSecurityGroup") is not None
    assert infra.get_resource("AWS::EC2::Instance.WebServer") is not None


# ---------------------------------------------------------------------------
# 4. EC2, S3, IAM, Lambda, and Security Group Resources
# ---------------------------------------------------------------------------


def test_4_ec2_s3_iam_lambda_security_group_resources():
    cloud_tier_yaml = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  CoreInstance:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: ami-99999999
  DataStore:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: raw-data-store
  ExecutionRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: lambda.amazonaws.com
            Action: sts:AssumeRole
  IngestionFunction:
    Type: AWS::Lambda::Function
    Properties:
      FunctionName: ingest-events
      Handler: index.handler
      Runtime: python3.11
  InstanceSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Allow inbound application traffic
"""
    parser = CloudFormationParser()
    infra = parser.parse(cloud_tier_yaml, filename="full_stack.yaml")

    assert infra.resource_count == 5
    for expected_type, name in [
        ("AWS::EC2::Instance", "CoreInstance"),
        ("AWS::S3::Bucket", "DataStore"),
        ("AWS::IAM::Role", "ExecutionRole"),
        ("AWS::Lambda::Function", "IngestionFunction"),
        ("AWS::EC2::SecurityGroup", "InstanceSecurityGroup"),
    ]:
        res = infra.get_resource(f"{expected_type}.{name}")
        assert res is not None
        assert res.provider == "aws"
        assert res.name == name


# ---------------------------------------------------------------------------
# 5. DependsOn Relationships
# ---------------------------------------------------------------------------


def test_5_dependson_relationships():
    depend_yaml = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  Database:
    Type: AWS::RDS::DBInstance
    Properties:
      DBInstanceClass: db.t3.micro
  LogBucket:
    Type: AWS::S3::Bucket
  AppCluster:
    Type: AWS::EC2::Instance
    DependsOn:
      - Database
      - LogBucket
    Properties:
      ImageId: ami-1234
  WorkerNode:
    Type: AWS::EC2::Instance
    DependsOn: Database
    Properties:
      ImageId: ami-5678
"""
    parser = CloudFormationParser()
    infra = parser.parse(depend_yaml, filename="deps.yaml")

    app = infra.get_resource("AWS::EC2::Instance.AppCluster")
    assert "Database" in app.relationships
    assert "LogBucket" in app.relationships

    worker = infra.get_resource("AWS::EC2::Instance.WorkerNode")
    assert "Database" in worker.relationships


# ---------------------------------------------------------------------------
# 6. Intrinsic Functions Represented in Long Form
# ---------------------------------------------------------------------------


def test_6_intrinsic_functions_long_form():
    intrinsics_yaml = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  DestinationBucket:
    Type: AWS::S3::Bucket
  ProcessingFunction:
    Type: AWS::Lambda::Function
    Properties:
      FunctionName:
        Fn::Sub: "${AWS::StackName}-processor"
      Description:
        Fn::Join:
          - " - "
          - ["Data processor", "v1.0"]
      Environment:
        Variables:
          TARGET_BUCKET:
            Ref: DestinationBucket
          BUCKET_ARN:
            Fn::GetAtt:
              - DestinationBucket
              - Arn
          AZ:
            Fn::Select:
              - 0
              - Fn::GetAZs: ""
          EXPORTED:
            Fn::ImportValue: SharedVpcId
          MAPPED_VAL:
            Fn::FindInMap: [RegionMap, "us-east-1", "AmiId"]
"""
    parser = CloudFormationParser()
    infra = parser.parse(intrinsics_yaml, filename="intrinsics_long.yaml")

    fn = infra.get_resource("AWS::Lambda::Function.ProcessingFunction")
    assert fn is not None

    # Verify structured preservation of long-form intrinsics
    props = fn.attributes
    assert "Fn::Sub" in props["FunctionName"]
    assert "Fn::Join" in props["Description"]

    env = props["Environment"]["Variables"]
    assert env["TARGET_BUCKET"] == {"Ref": "DestinationBucket"}
    assert env["BUCKET_ARN"] == {"Fn::GetAtt": ["DestinationBucket", "Arn"]}
    assert "Fn::Select" in env["AZ"]
    assert env["EXPORTED"] == {"Fn::ImportValue": "SharedVpcId"}
    assert env["MAPPED_VAL"] == {"Fn::FindInMap": ["RegionMap", "us-east-1", "AmiId"]}

    # Verify Ref and Fn::GetAtt contributed to relationships
    assert "DestinationBucket" in fn.relationships


# ---------------------------------------------------------------------------
# 7. YAML Short-Form Intrinsic Tags
# ---------------------------------------------------------------------------


def test_7_yaml_short_form_intrinsic_tags():
    short_tags_yaml = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  TargetBucket:
    Type: AWS::S3::Bucket
  ConfiguredInstance:
    Type: AWS::EC2::Instance
    Properties:
      UserData: !Base64 "#!/bin/bash\\necho hello"
      SubnetId: !Select [0, !GetAZs ""]
      IamRoleArn: !GetAtt TargetBucket.Arn
      InstanceType: !If [IsProduction, "t3.large", "t3.nano"]
      SecurityGroups:
        - !Ref TargetBucket
"""
    parser = CloudFormationParser()
    infra = parser.parse(short_tags_yaml, filename="short_tags.yaml")

    inst = infra.get_resource("AWS::EC2::Instance.ConfiguredInstance")
    assert inst is not None
    props = inst.attributes

    # !Base64 -> {"Fn::Base64": ...}
    assert "Fn::Base64" in props["UserData"]
    # !Select / !GetAZs
    assert "Fn::Select" in props["SubnetId"]
    assert "Fn::GetAZs" in props["SubnetId"]["Fn::Select"][1]
    # !GetAtt scalar dot notation -> {"Fn::GetAtt": ["TargetBucket", "Arn"]}
    assert props["IamRoleArn"] == {"Fn::GetAtt": ["TargetBucket", "Arn"]}
    # !If
    assert "Fn::If" in props["InstanceType"]
    # !Ref
    assert props["SecurityGroups"][0] == {"Ref": "TargetBucket"}

    # TargetBucket captured in relationships
    assert "TargetBucket" in inst.relationships


# ---------------------------------------------------------------------------
# 8. Missing Resources Section
# ---------------------------------------------------------------------------


def test_8_missing_resources():
    yaml_without_resources = """
AWSTemplateFormatVersion: '2010-09-09'
Description: Template without any resources section
Parameters:
  Env:
    Type: String
"""
    parser = CloudFormationParser()
    with pytest.raises(MalformedIaCError) as exc_info:
        parser.parse(yaml_without_resources, filename="no_res.yaml")
    assert "missing required 'Resources'" in str(exc_info.value)


# ---------------------------------------------------------------------------
# 9. Empty Resources Section
# ---------------------------------------------------------------------------


def test_9_empty_resources():
    yaml_empty_resources = """
AWSTemplateFormatVersion: '2010-09-09'
Resources: {}
"""
    parser = CloudFormationParser()
    with pytest.raises(MalformedIaCError) as exc_info:
        parser.parse(yaml_empty_resources, filename="empty_res.yaml")
    assert "must be a non-empty mapping" in str(exc_info.value)


# ---------------------------------------------------------------------------
# 10. Malformed YAML Syntax
# ---------------------------------------------------------------------------


def test_10_malformed_yaml():
    broken_yaml = """
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
    Properties: { unclosed bracket
"""
    parser = CloudFormationParser()
    with pytest.raises(MalformedIaCError) as exc_info:
        parser.parse(broken_yaml, filename="broken.yaml")
    assert "Invalid CloudFormation YAML syntax" in str(exc_info.value)


# ---------------------------------------------------------------------------
# 11. Malformed JSON Syntax
# ---------------------------------------------------------------------------


def test_11_malformed_json():
    broken_json = '{"Resources": {"MyBucket": {"Type": "AWS::S3::Bucket", broken json'
    parser = CloudFormationParser()
    with pytest.raises(MalformedIaCError) as exc_info:
        parser.parse(broken_json, filename="broken.json")
    assert "Invalid CloudFormation JSON syntax" in str(exc_info.value)


# ---------------------------------------------------------------------------
# 12. Generic YAML Rejection
# ---------------------------------------------------------------------------


def test_12_generic_yaml_rejection():
    generic_yaml = """
app:
  name: payment-service
  version: 2.1.0
  replicas: 4
database:
  host: postgres.internal
"""
    parser = CloudFormationParser()
    assert parser.can_parse("config.yaml", generic_yaml) is False

    with pytest.raises(UnsupportedFormatError) as exc_info:
        identify_iac_format("config.yaml", generic_yaml)
    assert "generic YAML file" in str(exc_info.value)


# ---------------------------------------------------------------------------
# 13. Generic JSON Rejection
# ---------------------------------------------------------------------------


def test_13_generic_json_rejection():
    generic_json = json.dumps({
        "name": "iac-risk-composer",
        "version": "1.0.0",
        "scripts": {"build": "vite build"}
    })
    parser = CloudFormationParser()
    assert parser.can_parse("package.json", generic_json) is False

    with pytest.raises(UnsupportedFormatError) as exc_info:
        identify_iac_format("package.json", generic_json)
    assert "generic JSON file" in str(exc_info.value)


# ---------------------------------------------------------------------------
# 14. Kubernetes YAML Rejection
# ---------------------------------------------------------------------------


def test_14_kubernetes_yaml_rejection():
    k8s_yaml = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-deployment
spec:
  replicas: 3
"""
    parser = CloudFormationParser()
    # CloudFormation parser must not claim Kubernetes manifests
    assert parser.can_parse("deployment.yaml", k8s_yaml) is False

    fmt = identify_iac_format("deployment.yaml", k8s_yaml)
    assert fmt == IaCFormat.KUBERNETES
    assert fmt != IaCFormat.CLOUDFORMATION


# ---------------------------------------------------------------------------
# 15. Terraform .tf Compatibility
# ---------------------------------------------------------------------------


def test_15_terraform_tf_compatibility():
    tf_hcl = """
resource "aws_s3_bucket" "prod_vault" {
  bucket = "company-prod-vault"
}
"""
    fmt = identify_iac_format("main.tf", tf_hcl)
    assert fmt == IaCFormat.TERRAFORM

    infra = parse_iac(tf_hcl, filename="main.tf")
    assert infra.source_format == "terraform"
    assert infra.resource_count == 1
    assert infra.resources[0].type == "aws_s3_bucket"


# ---------------------------------------------------------------------------
# 16. Terraform .tf.json Compatibility
# ---------------------------------------------------------------------------


def test_16_terraform_tf_json_compatibility():
    tf_json = json.dumps({
        "resource": {
            "aws_s3_bucket": {
                "json_vault": {
                    "bucket": "json-bucket-vault"
                }
            }
        }
    })
    fmt = identify_iac_format("infra.tf.json", tf_json)
    assert fmt == IaCFormat.TERRAFORM

    infra = parse_iac(tf_json, filename="infra.tf.json")
    assert infra.source_format == "terraform"
    assert infra.resource_count == 1


# ---------------------------------------------------------------------------
# 17. Registry Selecting CloudFormation Correctly
# ---------------------------------------------------------------------------


def test_17_registry_selecting_cloudformation_correctly():
    fmt_yaml = identify_iac_format("template.yaml", SAMPLE_CFN_YAML)
    assert fmt_yaml == IaCFormat.CLOUDFORMATION

    fmt_json = identify_iac_format("template.json", SAMPLE_CFN_JSON)
    assert fmt_json == IaCFormat.CLOUDFORMATION

    resolved_parser = default_parser_registry.get_parser_for_file("template.yaml", SAMPLE_CFN_YAML)
    assert isinstance(resolved_parser, CloudFormationParser)


# ---------------------------------------------------------------------------
# 18. /api/analyze Endpoint Compatibility with CloudFormation
# ---------------------------------------------------------------------------


def test_18_api_analyze_accepting_cloudformation_template():
    cfn_upload = """
AWSTemplateFormatVersion: '2010-09-09'
Description: Production Stack
Resources:
  SecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Inbound HTTP
  WebServerInstance:
    Type: AWS::EC2::Instance
    DependsOn: SecurityGroup
    Properties:
      ImageId: ami-12345678
"""
    res = client.post(
        "/api/analyze",
        files={"file": ("stack.yaml", cfn_upload.encode("utf-8"), "application/x-yaml")},
    )
    assert res.status_code == 200
    data = res.json()

    assert data["filename"] == "stack.yaml"
    assert data["resource_count"] == 2
    assert "resources" in data
    assert len(data["resources"]) == 2
    assert "infrastructure_map" in data
    assert "threat_findings" in data
    assert "risk_summary" in data
    assert "risk_explanations" in data
    assert "remediations" in data
    assert data["id"] is not None
    assert data["id"].startswith("RPT-")
