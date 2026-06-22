# aws_audit_basic.py - Felix Chirchir
# Week 2 Day 1 - Basic AWS Security Audit using boto3
# boto3 is the Python library for AWS — same as AWS CLI but in Python

import boto3
import json
from datetime import datetime

# ============================================
# WHAT IS boto3?
# boto3 is AWS's official Python SDK (Software Development Kit)
# It lets Python talk directly to AWS APIs
# Every AWS CLI command has an equivalent boto3 call
# aws iam list-users → boto3 iam.list_users()
# ============================================

# ============================================
# CONNECTING TO AWS WITH boto3
# boto3 automatically reads your credentials from
# ~/.aws/credentials (set by aws configure)
# You never hardcode credentials in your code
# ============================================

def get_aws_clients():
    """
    Creates and returns AWS service clients.
    Each client connects to one AWS service.
    """
    iam = boto3.client('iam')
    sts = boto3.client('sts')
    s3 = boto3.client('s3')
    return iam, sts, s3

# ============================================
# CHECK 1 - Who are we connected as?
# ============================================
def check_identity(sts):
    """
    Verifies our AWS connection and returns account info.
    Always run this first in any audit script.
    """
    print("\n--- AWS IDENTITY CHECK ---")
    identity = sts.get_caller_identity()
    print(f"Account ID: {identity['Account']}")
    print(f"User ARN:   {identity['Arn']}")
    print(f"User ID:    {identity['UserId']}")
    return identity['Account']

# ============================================
# CHECK 2 - Password policy audit
# ============================================
def check_password_policy(iam):
    """
    Checks the account password policy.
    Weak policies = easy to crack passwords = account takeover risk.
    CIS AWS Benchmark requires minimum 14 characters.
    """
    print("\n--- PASSWORD POLICY AUDIT ---")
    findings = []

    try:
        policy = iam.get_account_password_policy()['PasswordPolicy']

        min_length = policy.get('MinimumPasswordLength', 0)
        requires_uppercase = policy.get('RequireUppercaseCharacters', False)
        requires_lowercase = policy.get('RequireLowercaseCharacters', False)
        requires_numbers = policy.get('RequireNumbers', False)
        requires_symbols = policy.get('RequireSymbols', False)
        max_age = policy.get('MaxPasswordAge', 0)
        reuse_prevention = policy.get('PasswordReusePrevention', 0)

        print(f"Minimum length:      {min_length}")
        print(f"Requires uppercase:  {requires_uppercase}")
        print(f"Requires numbers:    {requires_numbers}")
        print(f"Requires symbols:    {requires_symbols}")
        print(f"Max password age:    {max_age} days")
        print(f"Prevent reuse:       {reuse_prevention} passwords")

        # Check against best practices
        if min_length < 14:
            findings.append({
                "title": "Password minimum length below 14 characters",
                "severity": "HIGH",
                "current_value": str(min_length),
                "recommended": "14 or more",
                "description": "Short passwords are easier to crack via brute force",
                "reference": "CIS AWS Benchmark 1.8"
            })

        if not requires_symbols:
            findings.append({
                "title": "Password policy does not require symbols",
                "severity": "MEDIUM",
                "current_value": "False",
                "recommended": "True",
                "description": "Passwords without symbols are weaker",
                "reference": "CIS AWS Benchmark 1.9"
            })

        if max_age == 0 or max_age > 90:
            findings.append({
                "title": "Password expiry not set or exceeds 90 days",
                "severity": "MEDIUM",
                "current_value": str(max_age),
                "recommended": "90 days maximum",
                "description": "Old passwords increase risk of credential compromise",
                "reference": "CIS AWS Benchmark 1.11"
            })

    except iam.exceptions.NoSuchEntityException:
        findings.append({
            "title": "No IAM password policy configured",
            "severity": "CRITICAL",
            "current_value": "None",
            "recommended": "Strong policy required",
            "description": "Without a password policy users can set weak passwords",
            "reference": "CIS AWS Benchmark 1.8"
        })
        print("WARNING: No password policy set")

    return findings

# ============================================
# CHECK 3 - IAM users audit
# ============================================
def check_iam_users(iam):
    """
    Reviews all IAM users for security issues.
    Checks: MFA status, access key age, console access.
    """
    print("\n--- IAM USERS AUDIT ---")
    findings = []

    users = iam.list_users()['Users']
    print(f"Total IAM users: {len(users)}")

    for user in users:
        username = user['UserName']
        print(f"\n  Checking user: {username}")

        # Check MFA status
        mfa_devices = iam.list_mfa_devices(
            UserName=username
        )['MFADevices']

        if not mfa_devices:
            findings.append({
                "title": f"MFA not enabled for user: {username}",
                "severity": "HIGH",
                "current_value": "MFA disabled",
                "recommended": "MFA enabled",
                "description": "Without MFA password compromise = account takeover",
                "reference": "CIS AWS Benchmark 1.10"
            })
            print(f"    WARNING: No MFA")
        else:
            print(f"    PASS: MFA enabled")

        # Check access keys
        access_keys = iam.list_access_keys(
            UserName=username
        )['AccessKeyMetadata']

        for key in access_keys:
            key_id = key['AccessKeyId']
            status = key['Status']
            created = key['CreateDate']

            # Calculate key age in days
            age_days = (datetime.now(created.tzinfo) - created).days

            print(f"    Access key: {key_id[:8]}... "
                  f"Status: {status}, Age: {age_days} days")

            if age_days > 90:
                findings.append({
                    "title": f"Access key older than 90 days: {username}",
                    "severity": "HIGH",
                    "current_value": f"{age_days} days old",
                    "recommended": "Rotate every 90 days",
                    "description": "Old access keys increase compromise risk",
                    "reference": "CIS AWS Benchmark 1.14"
                })

            if status == "Inactive":
                findings.append({
                    "title": f"Inactive access key exists: {username}",
                    "severity": "MEDIUM",
                    "current_value": "Inactive key not deleted",
                    "recommended": "Delete unused keys",
                    "description": "Unused keys should be removed to reduce attack surface",
                    "reference": "CIS AWS Benchmark 1.13"
                })

    return findings

# ============================================
# CHECK 4 - S3 bucket public access
# ============================================
def check_s3_buckets(s3):
    """
    Checks all S3 buckets for public access settings.
    Public S3 buckets are one of the most common AWS security issues.
    Many major data breaches started with a public S3 bucket.
    """
    print("\n--- S3 BUCKET AUDIT ---")
    findings = []

    try:
        buckets = s3.list_buckets()['Buckets']
        print(f"Total S3 buckets: {len(buckets)}")

        if not buckets:
            print("  No buckets found")
            return findings

        for bucket in buckets:
            bucket_name = bucket['Name']
            print(f"\n  Checking bucket: {bucket_name}")

            # Check public access block settings
            try:
                public_access = s3.get_public_access_block(
                    Bucket=bucket_name
                )['PublicAccessBlockConfiguration']

                block_public_acls = public_access.get(
                    'BlockPublicAcls', False)
                ignore_public_acls = public_access.get(
                    'IgnorePublicAcls', False)
                block_public_policy = public_access.get(
                    'BlockPublicPolicy', False)
                restrict_public_buckets = public_access.get(
                    'RestrictPublicBuckets', False)

                all_blocked = all([
                    block_public_acls,
                    ignore_public_acls,
                    block_public_policy,
                    restrict_public_buckets
                ])

                if all_blocked:
                    print(f"    PASS: All public access blocked")
                else:
                    findings.append({
                        "title": f"S3 bucket not fully blocking public access: {bucket_name}",
                        "severity": "CRITICAL",
                        "current_value": str(public_access),
                        "recommended": "All 4 settings set to True",
                        "description": "Publicly accessible S3 can expose sensitive data",
                        "reference": "CIS AWS Benchmark 2.1.5"
                    })
                    print(f"    CRITICAL: Public access not fully blocked")

            except s3.exceptions.NoSuchPublicAccessBlockConfiguration:
                findings.append({
                    "title": f"S3 bucket has no public access block: {bucket_name}",
                    "severity": "CRITICAL",
                    "current_value": "No configuration",
                    "recommended": "Enable all 4 public access block settings",
                    "description": "Without this setting bucket may be publicly accessible",
                    "reference": "CIS AWS Benchmark 2.1.5"
                })
                print(f"    CRITICAL: No public access block configured")

            # Check bucket encryption
            try:
                encryption = s3.get_bucket_encryption(
                    Bucket=bucket_name
                )
                print(f"    PASS: Encryption enabled")

            except Exception:
                findings.append({
                    "title": f"S3 bucket not encrypted: {bucket_name}",
                    "severity": "HIGH",
                    "current_value": "No encryption",
                    "recommended": "Enable SSE-S3 or SSE-KMS",
                    "description": "Unencrypted data at rest can be read if physically accessed",
                    "reference": "CIS AWS Benchmark 2.1.1"
                })
                print(f"    HIGH: No encryption")

    except Exception as e:
        print(f"  Error checking S3: {str(e)}")

    return findings

# ============================================
# GENERATE REPORT
# ============================================
def generate_report(all_findings, account_id):
    """
    Generates a professional report from all findings.
    Organizes by severity for easy reading.
    """
    print("\n" + "=" * 65)
    print("AWS SECURITY AUDIT REPORT")
    print("=" * 65)
    print(f"Account:  {account_id}")
    print(f"Date:     {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Auditor:  Felix Chirchir")
    print(f"Tool:     Felix AWS Auditor v1.0")
    print("=" * 65)

    # Count by severity
    critical = [f for f in all_findings if f["severity"] == "CRITICAL"]
    high = [f for f in all_findings if f["severity"] == "HIGH"]
    medium = [f for f in all_findings if f["severity"] == "MEDIUM"]
    low = [f for f in all_findings if f["severity"] == "LOW"]

    print(f"\nSUMMARY")
    print(f"Total findings: {len(all_findings)}")
    print(f"Critical:       {len(critical)}")
    print(f"High:           {len(high)}")
    print(f"Medium:         {len(medium)}")
    print(f"Low:            {len(low)}")

    # Print findings by severity
    for severity, findings_list in [
        ("CRITICAL", critical),
        ("HIGH", high),
        ("MEDIUM", medium),
        ("LOW", low)
    ]:
        if findings_list:
            print(f"\n{'='*40}")
            print(f"{severity} FINDINGS ({len(findings_list)})")
            print(f"{'='*40}")
            for i, finding in enumerate(findings_list, 1):
                print(f"\n  {i}. {finding['title']}")
                print(f"     Current:    {finding['current_value']}")
                print(f"     Recommended:{finding['recommended']}")
                print(f"     Risk:       {finding['description']}")
                print(f"     Reference:  {finding['reference']}")

    print("\n" + "=" * 65)
    print("END OF REPORT")
    print("=" * 65)

    # Save to file
    report_file = f"aws_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_file, "w") as f:
        json.dump({
            "account_id": account_id,
            "audit_date": datetime.now().isoformat(),
            "auditor": "Felix Chirchir",
            "total_findings": len(all_findings),
            "findings": all_findings
        }, f, indent=4)
    print(f"\nReport saved to: {report_file}")

# ============================================
# MAIN PROGRAM
# ============================================
def main():
    print("=" * 65)
    print("FELIX AWS SECURITY AUDITOR v1.0")
    print("Week 2 Day 1 — boto3 + AWS Security")
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 65)

    # Connect to AWS
    print("\nConnecting to AWS...")
    iam, sts, s3 = get_aws_clients()

    # Check identity
    account_id = check_identity(sts)

    # Run all security checks
    all_findings = []

    password_findings = check_password_policy(iam)
    all_findings.extend(password_findings)

    iam_findings = check_iam_users(iam)
    all_findings.extend(iam_findings)

    s3_findings = check_s3_buckets(s3)
    all_findings.extend(s3_findings)

    # Generate report
    generate_report(all_findings, account_id)

if __name__ == "__main__":
    main()