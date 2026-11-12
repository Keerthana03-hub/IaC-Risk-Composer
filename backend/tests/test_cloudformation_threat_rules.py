"""
tests/test_cloudformation_threat_rules.py
-----------------------------------------
Unit tests for AWS CloudFormation Security Threat Detection Rules (Stage 5).
Covers CFN-001 through CFN-006, explicit insecure settings, clean/secure settings,
unspecified values, detection status, confidence, and remediation suggestions.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Ensure backend root is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from services.cloudformation_parser import CloudFormationParser
from services.remediation_engine import generate_remediations
from services.risk_engine import assess_risks
from services.threat_engine import analyze_threats


# ---------------------------------------------------------------------------
# CFN-001: Public S3 Bucket Exposure
# ---------------------------------------------------------------------------


def test_cfn_001_s3_public_acl_and_policy():
    """Detect S3 bucket with PublicRead ACL and public bucket policy."""
    yaml_tmpl = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  PublicBucket:
    Type: AWS::S3::Bucket
    Properties:
      AccessControl: PublicRead
  BucketPolicy:
    Type: AWS::S3::BucketPolicy
    Properties:
      Bucket: !Ref PublicBucket
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal: '*'
            Action: 's3:GetObject'
            Resource: 'arn:aws:s3:::my-bucket/*'
"""
    parser = CloudFormationParser()
    infra = parser.parse(yaml_tmpl, filename="s3_public.yaml")
    findings = analyze_threats(infra.to_legacy_resources(), source_format="cloudformation")

    cfn_001 = [f for f in findings if f["threat_id"] == "CFN-001"]
    assert len(cfn_001) == 2  # 1 from ACL, 1 from BucketPolicy

    acl_f = [f for f in cfn_001 if "acl" in f["finding_id"]][0]
    assert acl_f["severity"] == "High"
    assert acl_f["detection_status"] == "Confirmed"
    assert acl_f["evidence"]["AccessControl"] == "PublicRead"
    assert acl_f["source_format"] == "cloudformation"

    pol_f = [f for f in cfn_001 if "policy" in f["finding_id"]][0]
    assert pol_f["severity"] == "Critical"
    assert pol_f["detection_status"] == "Confirmed"


def test_cfn_001_pab_disabled():
    """Detect S3 bucket with explicitly disabled PublicAccessBlock."""
    yaml_tmpl = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  OpenBucket:
    Type: AWS::S3::Bucket
    Properties:
      PublicAccessBlockConfiguration:
        BlockPublicAcls: false
        IgnorePublicAcls: false
"""
    parser = CloudFormationParser()
    infra = parser.parse(yaml_tmpl, filename="s3_pab.yaml")
    findings = analyze_threats(infra.to_legacy_resources(), source_format="cloudformation")

    f = [f for f in findings if f["threat_id"] == "CFN-001"][0]
    assert f["severity"] == "High"
    assert "BlockPublicAcls" in f["evidence"]["disabled_settings"]


def test_cfn_001_clean_bucket_not_flagged():
    """Clean private S3 bucket is not flagged as public."""
    yaml_tmpl = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  PrivateBucket:
    Type: AWS::S3::Bucket
    Properties:
      AccessControl: Private
      PublicAccessBlockConfiguration:
        BlockPublicAcls: true
        BlockPublicPolicy: true
        IgnorePublicAcls: true
        RestrictPublicBuckets: true
"""
    parser = CloudFormationParser()
    infra = parser.parse(yaml_tmpl, filename="clean_s3.yaml")
    findings = analyze_threats(infra.to_legacy_resources(), source_format="cloudformation")

    assert not any(f["threat_id"] == "CFN-001" for f in findings)


# ---------------------------------------------------------------------------
# CFN-002: Missing S3 Server-Side Encryption
# ---------------------------------------------------------------------------


def test_cfn_002_missing_s3_encryption():
    """Detect S3 bucket without BucketEncryption (Medium, Needs Review)."""
    yaml_tmpl = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  UnencryptedBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: raw-data-unencrypted
"""
    parser = CloudFormationParser()
    infra = parser.parse(yaml_tmpl, filename="s3_noenc.yaml")
    findings = analyze_threats(infra.to_legacy_resources(), source_format="cloudformation")

    f = [f for f in findings if f["threat_id"] == "CFN-002"][0]
    assert f["severity"] == "Medium"
    assert f["detection_status"] == "Needs Review"
    assert f["confidence"] == "Medium"
    assert f["evidence"]["BucketEncryption"] == "missing"


def test_cfn_002_encrypted_bucket_not_flagged():
    """Bucket with ServerSideEncryptionConfiguration is not flagged."""
    yaml_tmpl = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  EncryptedBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketEncryption:
        ServerSideEncryptionConfiguration:
          - ServerSideEncryptionByDefault:
              SSEAlgorithm: AES256
"""
    parser = CloudFormationParser()
    infra = parser.parse(yaml_tmpl, filename="s3_enc.yaml")
    findings = analyze_threats(infra.to_legacy_resources(), source_format="cloudformation")

    assert not any(f["threat_id"] == "CFN-002" for f in findings)


# ---------------------------------------------------------------------------
# CFN-003: Overly Permissive IAM Policy
# ---------------------------------------------------------------------------


def test_cfn_003_iam_wildcards():
    """Detect wildcard Action (*) and Resource (*) in IAM policies."""
    yaml_tmpl = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  AdminRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: ec2.amazonaws.com
            Action: 'sts:AssumeRole'
      Policies:
        - PolicyName: RootAccess
          PolicyDocument:
            Statement:
              - Effect: Allow
                Action: '*'
                Resource: '*'
"""
    parser = CloudFormationParser()
    infra = parser.parse(yaml_tmpl, filename="iam.yaml")
    findings = analyze_threats(infra.to_legacy_resources(), source_format="cloudformation")

    f = [f for f in findings if f["threat_id"] == "CFN-003"][0]
    assert f["severity"] == "Critical"
    assert f["detection_status"] == "Confirmed"
    assert f["confidence"] == "High"


# ---------------------------------------------------------------------------
# CFN-004: Publicly Accessible EC2 Security Group
# ---------------------------------------------------------------------------


def test_cfn_004_security_group_ssh_rdp_and_all_ports():
    """Detect unrestricted SSH (Critical), RDP (Critical), and web (High)."""
    yaml_tmpl = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  WideOpenSG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Public access SG
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 22
          ToPort: 22
          CidrIp: 0.0.0.0/0
        - IpProtocol: tcp
          FromPort: 3389
          ToPort: 3389
          CidrIp: 0.0.0.0/0
        - IpProtocol: tcp
          FromPort: 80
          ToPort: 80
          CidrIp: 0.0.0.0/0
"""
    parser = CloudFormationParser()
    infra = parser.parse(yaml_tmpl, filename="sg.yaml")
    findings = analyze_threats(infra.to_legacy_resources(), source_format="cloudformation")

    sg_findings = [f for f in findings if f["threat_id"] == "CFN-004"]
    assert len(sg_findings) == 3

    # SSH (port 22) -> Critical
    ssh_f = [f for f in sg_findings if f["evidence"]["from_port"] == 22][0]
    assert ssh_f["severity"] == "Critical"

    # RDP (port 3389) -> Critical
    rdp_f = [f for f in sg_findings if f["evidence"]["from_port"] == 3389][0]
    assert rdp_f["severity"] == "Critical"

    # HTTP (port 80) -> High
    http_f = [f for f in sg_findings if f["evidence"]["from_port"] == 80][0]
    assert http_f["severity"] == "High"


def test_cfn_004_restricted_sg_not_flagged():
    """Security group with private CIDR (10.0.0.0/8) is not flagged."""
    yaml_tmpl = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  PrivateSG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Internal only
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 22
          ToPort: 22
          CidrIp: 10.0.0.0/8
"""
    parser = CloudFormationParser()
    infra = parser.parse(yaml_tmpl, filename="private_sg.yaml")
    findings = analyze_threats(infra.to_legacy_resources(), source_format="cloudformation")

    assert not any(f["threat_id"] == "CFN-004" for f in findings)


# ---------------------------------------------------------------------------
# CFN-005: Unencrypted EBS Storage Volume
# ---------------------------------------------------------------------------


def test_cfn_005_ebs_volume_encryption():
    """Encrypted: false is High/Confirmed; omitted is Medium/Needs Review."""
    yaml_tmpl = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  ExplicitUnencryptedVol:
    Type: AWS::EC2::Volume
    Properties:
      Size: 100
      Encrypted: false
  OmittedEncryptedVol:
    Type: AWS::EC2::Volume
    Properties:
      Size: 50
"""
    parser = CloudFormationParser()
    infra = parser.parse(yaml_tmpl, filename="ebs.yaml")
    findings = analyze_threats(infra.to_legacy_resources(), source_format="cloudformation")

    ebs_findings = [f for f in findings if f["threat_id"] == "CFN-005"]
    assert len(ebs_findings) == 2

    explicit_f = [f for f in ebs_findings if f["affected_resource_name"] == "ExplicitUnencryptedVol"][0]
    assert explicit_f["severity"] == "High"
    assert explicit_f["detection_status"] == "Confirmed"
    assert explicit_f["evidence"]["Encrypted"] is False

    omitted_f = [f for f in ebs_findings if f["affected_resource_name"] == "OmittedEncryptedVol"][0]
    assert omitted_f["severity"] == "Medium"
    assert omitted_f["detection_status"] == "Needs Review"


# ---------------------------------------------------------------------------
# CFN-006: Insecure Lambda Configuration
# ---------------------------------------------------------------------------


def test_cfn_006_lambda_configuration():
    """Detect Lambda Url with AuthType: NONE (High) and TracingConfig PassThrough (Medium)."""
    yaml_tmpl = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  PublicUrlFunction:
    Type: AWS::Lambda::Function
    Properties:
      FunctionName: payment-processor
      TracingConfig:
        Mode: PassThrough
  PublicUrl:
    Type: AWS::Lambda::Url
    Properties:
      TargetFunctionArn: !GetAtt PublicUrlFunction.Arn
      AuthType: NONE
"""
    parser = CloudFormationParser()
    infra = parser.parse(yaml_tmpl, filename="lambda.yaml")
    findings = analyze_threats(infra.to_legacy_resources(), source_format="cloudformation")

    lambda_findings = [f for f in findings if f["threat_id"] == "CFN-006"]
    assert len(lambda_findings) == 2

    url_f = [f for f in lambda_findings if "public-url" in f["finding_id"]][0]
    assert url_f["severity"] == "High"
    assert url_f["detection_status"] == "Confirmed"
    assert url_f["evidence"]["AuthType"] == "NONE"

    tracing_f = [f for f in lambda_findings if "tracing" in f["finding_id"]][0]
    assert tracing_f["severity"] == "Medium"


def test_cfn_remediation_generation():
    """Verify remediation engine provides safe code snippets for CloudFormation findings."""
    yaml_tmpl = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  UnencryptedVault:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: corp-vault-unencrypted
"""
    parser = CloudFormationParser()
    infra = parser.parse(yaml_tmpl, filename="s3_rem.yaml")
    findings = analyze_threats(infra.to_legacy_resources(), source_format="cloudformation")
    assessed, _ = assess_risks(findings)
    rems = generate_remediations(assessed, infra.to_legacy_resources())

    assert len(rems) >= 1
    rem = rems[0]
    assert rem["patch_type"] in ("addition", "modification", "manual")
    assert rem["suggested_code"] is not None
    assert "BucketEncryption" in rem["suggested_code"]
