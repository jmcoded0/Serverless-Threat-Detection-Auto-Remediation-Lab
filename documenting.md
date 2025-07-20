
## ⚙️ Phase 1: Infrastructure Setup with Terraform

In this phase, I created the base setup for my Serverless Remediation Lab. The goal was to simulate an insecure S3 bucket, and prepare the automation stack (Lambda + S3 Trigger) to respond to misconfigurations like public access.

---

### 🔹 Step 1: Project Folder Structure

I created a new folder and added Terraform config files along with a folder for the Lambda script.

```bash
mkdir serverless-remediation-lab
cd serverless-remediation-lab
touch main.tf variables.tf outputs.tf
mkdir lambda
```

> 📸 Screenshot: Project folder structure showing `main.tf`, `variables.tf`, `outputs.tf`, and `lambda/` folder
<img width="1116" height="798" alt="VirtualBox_Kali Linux_19_07_2025_23_33_40" src="https://github.com/user-attachments/assets/7177bb9c-0dba-4828-8b3d-a1fe055bcdab" />

---
Below is the main infrastructure definition, broken into IAM, Lambda, S3 bucket, and event trigger blocks.
### 🔹 Step 2: Writing Terraform Configuration (main.tf)

I used `main.tf` to define:
- AWS provider
- S3 bucket (intentionally misconfigured)
- Lambda + S3 bucket + permissions and trigger

```hcl
provider "aws" {
  region = "us-east-1"
}

# Create S3 bucket
resource "aws_s3_bucket" "target_bucket" {
  bucket = "jmcoded-insecure-public-bucket-001"
  force_destroy = true
}

# Disable Block Public Access for the bucket (Fix for AccessDenied issue)
resource "aws_s3_bucket_public_access_block" "public_access" {
  bucket = aws_s3_bucket.target_bucket.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# Set ownership controls (optional but common)
resource "aws_s3_bucket_ownership_controls" "ownership" {
  bucket = aws_s3_bucket.target_bucket.id

  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

# Make bucket publicly readable (this is the policy that was getting blocked)
resource "aws_s3_bucket_policy" "public_read_policy" {
  bucket = aws_s3_bucket.target_bucket.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid       = "PublicReadGetObject",
        Effect    = "Allow",
        Principal = "*",
        Action    = "s3:GetObject",
        Resource  = "${aws_s3_bucket.target_bucket.arn}/*"
      }
    ]
  })
}

# IAM Role for Lambda
resource "aws_iam_role" "lambda_exec_role" {
  name = "lambda_exec_role_jmcoded"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Principal = {
          Service = "lambda.amazonaws.com"
        },
        Action = "sts:AssumeRole"
      }
    ]
  })
}

# Attach basic execution policy to the role
resource "aws_iam_role_policy_attachment" "lambda_basic_policy" {
  role       = aws_iam_role.lambda_exec_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

```

> 📸 Screenshot: VS Code showing full `main.tf` with provider, S3, and Lambda trigger
<img width="1920" height="909" alt="VirtualBox_Kali Linux_20_07_2025_03_26_29" src="https://github.com/user-attachments/assets/1e023418-6deb-4bae-a826-ce9046482671" />

---
### 📄Step 3: `variables.tf` — Terraform Variables for Deployment

This file defines key variables used in the deployment process. By setting them here, we keep the configuration clean and reusable.

```hcl
variable "aws_region" {
  description = "The AWS region to deploy to"
  type        = string
  default     = "us-east-1"
}

variable "lambda_function_name" {
  description = "The name of the Lambda function"
  type        = string
  default     = "remediate-public-s3"
}

variable "iam_role_name" {
  description = "The name of the IAM role for Lambda execution"
  type        = string
  default     = "lambda-s3-remediation-role"
}
variable "target_bucket_name" {
  description = "The name of the insecure bucket"
  type        = string
}

```
<img width="1116" height="798" alt="VirtualBox_Kali Linux_20_07_2025_00_00_45" src="https://github.com/user-attachments/assets/fce8dff9-646d-4c38-a0ff-1aeb81113f65" />

🔍 **Breakdown**

- `aws_region`: Specifies the AWS region where Terraform will deploy all resources.
- `lambda_function_name`: The name of the Lambda function that will run the S3 remediation logic.
- `iam_role_name`: The IAM role that gives the Lambda function permission to act (like checking/modifying S3 buckets).

### 📄 `outputs.tf` — Terraform Output Values

This file is used to print key information after deployment. It helps confirm that everything worked and shows important resource names or ARNs.

```hcl
output "lambda_function_name" {
  value = aws_lambda_function.remediate_s3.function_name
}

output "lambda_function_arn" {
  value = aws_lambda_function.remediate_s3.arn
}

```
<img width="1116" height="798" alt="VirtualBox_Kali Linux_20_07_2025_00_12_47" src="https://github.com/user-attachments/assets/05d56ad5-f6a2-4a44-82b0-a8b2fc0b99ff" />

🔍 **Breakdown**

- `lambda_function_name`: Displays the actual name of the Lambda function after deployment.
- `lambda_function_arn`: Shows the full Amazon Resource Name (ARN), which uniquely identifies the Lambda function across AWS.

🧠  These outputs make it easy to grab values for monitoring, logging, or future integrations.
Then add a short section for terraform.tfvars:

### 📄 `terraform.tfvars` — Values Injected at Deploy Time

I created a terraform.tfvars file to pass the actual S3 bucket name into the configuration during deployment.
```
target_bucket_name = "my-insecure-public-bucket"
```
<img width="1116" height="798" alt="VirtualBox_Kali Linux_20_07_2025_00_35_07" src="https://github.com/user-attachments/assets/53dd015c-5420-486f-83b9-32ebdba0bc7a" />

🧠 This setup keeps the `main.tf` clean and lets us update values easily without touching the main configuration.

## ⚙️ Phase 1.5: Creating and Zipping the Lambda Remediation Bot

Before running `terraform apply`, I needed to create the actual Python bot that Terraform will deploy as an AWS Lambda function. Terraform is expecting a file called `lambda.zip`, which will contain this logic.

---

### 🧾 Step 1: Create the Lambda Script (`lambda_function.py`)

I started by creating the file:

```bash
nano lambda_function.py
```

Then I pasted the following Python code:

```python
import boto3

def lambda_handler(event, context):
    s3 = boto3.client('s3')
    for record in event['Records']:
        bucket = record['s3']['bucket']['name']
        key = record['s3']['object']['key']
        
        # Revoke public-read access by making the object private
        s3.put_object_acl(Bucket=bucket, Key=key, ACL='private')
    
    return {
        'statusCode': 200,
        'body': 'Public access removed.'
    }
```

✅ After saving and exiting (`CTRL + O`, `Enter`, then `CTRL + X`), I moved on to zip the file.
<img width="1116" height="798" alt="VirtualBox_Kali Linux_20_07_2025_01_38_19" src="https://github.com/user-attachments/assets/f163c8f4-b7a2-4ed6-a22c-8c640e6e5e1b" />

---

### 🧰 Step 2: Zip the Lambda Script

I zipped the Python file so Terraform can upload it to AWS:

```bash
zip lambda.zip lambda_function.py
```

This generated the `lambda.zip` archive. This file is referenced inside the Terraform config:

```hcl
source_code_hash = filebase64sha256("lambda.zip")
```

---

✅ With the bot zipped and ready, I ran:

```bash
terraform plan
```

and then:

```bash
terraform apply
```

No more errors — Lambda was deployed correctly!

### 🔹 Step 4: Terraform Init & Apply

Once the files were saved, I initialized and deployed the infrastructure:

```bash
terraform init
terraform plan
terraform apply
```

> 📸 Screenshot: `terraform init` and `terraform apply` running successfully in terminal  
<img width="1116" height="798" alt="VirtualBox_Kali Linux_20_07_2025_03_14_50" src="https://github.com/user-attachments/assets/dd0a43df-5a23-48b2-8689-130511e79fb1" />

---

✅ **Phase 1 Complete — S3 bucket and Lambda trigger are live. Next, I’ll configure the Lambda (`remediate.py`) that listens for public access and auto-remediates it.
---

## ✅ Phase 1 Recap: Misconfigured S3 Bucket + Lambda Remediation Setup

In this phase, I used Terraform to deploy a misconfigured S3 bucket and a Lambda-based remediation function.

### 🔧 What I Set Up

- A vulnerable S3 bucket named `jmcoded-insecure-public-bucket-001` with **public-read access** via a bucket policy.
- A Lambda function (`remediate_s3`) that is designed to trigger automatically when a new object is uploaded.
- An IAM execution role with the necessary permissions for the Lambda function.
- All infrastructure was deployed using Terraform with clean modular files:
  - `main.tf`
  - `variables.tf`
  - `outputs.tf`
  - `terraform.tfvars`

### 📌 Key Objective

The goal here was to simulate a common S3 misconfiguration — exposing objects to the public — and set up an **automatic response** using AWS Lambda.

No actual uploads or testing were done yet. That comes in the next phase.

---

✅ Setup complete. The misconfigured bucket and Lambda function are now live. Next step: simulate attacker behavior and confirm Lambda auto-remediation works as expected.

---
## ⚔️ Phase 2: Simulating the Attack and Testing Auto-Remediation

Now that the S3 bucket, Lambda function, and CloudTrail are all properly deployed using Terraform, it’s time to simulate a real-world misconfiguration scenario. The goal of this phase is to test whether the Lambda function correctly detects public file uploads and revokes the `public-read` access automatically.

---

### 📁 Step 1: Upload a Public File to the Bucket

I created a simple test file (`payload.txt`) and uploaded it to the insecure bucket with public access enabled:

```bash
echo "Sensitive info inside" > payload.txt

aws s3 cp payload.txt s3://jmcoded-insecure-public-bucket-001/payload.txt --acl public-read
```
<img width="1116" height="798" alt="VirtualBox_Kali Linux_20_07_2025_03_49_41" src="https://github.com/user-attachments/assets/2c306ed9-bfd7-4e16-b234-d8e1778914bb" />

This simulates a real-world mistake where someone uploads sensitive data to a public-facing S3 bucket — exactly the type of event we want to catch and remediate.

---

### 📜 Step 2: Monitor CloudTrail for Event Logs

After uploading the file, I opened the AWS Console and GuardDuty automatically detected and alerted the S3 misconfiguration as a potential breach.

### 🚨 Detection Summary

- **Tool**: Amazon GuardDuty
- **Finding**: Public Anonymous Access Granted to S3 Bucket
- **Bucket Name**: `jmcoded-insecure-public-bucket-001`
- **Detection Type**: `Policy:S3/BucketAnonymousAccessGranted`
- **User Responsible**: `AdminUser`
- **API Call**: `PutBucketPolicy`
- **Time**: `07-20-2025 03:21 UTC`
- **Public IP**: `102.88.107.71 (MTN Nigeria)`
- **Region**: `us-east-1`
- **Severity**: HIGH

### 🖼️ Screenshot
<img width="960" height="505" alt="Screenshot 2025-07-20 041206" src="https://github.com/user-attachments/assets/ee5f4ad0-17f3-4974-895a-aa01285bbbaa" />

*Include screenshot of the full GuardDuty finding here.*

---

> ✅ This validates that the misconfigured S3 bucket was correctly detected by AWS native threat detection. We use this as proof of breach detection in this lab.
✅ **Confirmed** that the file upload was logged properly, including the `public-read` permission.

---

### ⚙️ Step 3: Lambda Trigger & Auto-Remediation

Next, I checked the **CloudWatch Logs** under `/aws/lambda/<lambda_function_name>`.

📌 The Lambda function got triggered automatically right after the `PutObject` event.

In the logs, I saw output indicating it had detected the public-read ACL and successfully removed it using the `PutObjectAcl` API call.

---

### ❌ Step 4: Verify That Public Access Was Removed

To verify the remediation, I tried accessing the file from a public browser link:

```
https://jmcoded-insecure-public-bucket-001.s3.amazonaws.com/payload.txt
```

Instead of showing the file, I got:

```
AccessDenied
```

💯 That confirmed the Lambda function worked exactly as intended — it revoked the public-read access automatically without manual intervention.

---

### 📸 Screenshots Collected

- Terminal output of `aws s3 cp`
- CloudTrail Event History showing the `PutObject`
- CloudWatch Logs showing Lambda trigger
- Screenshot of the “AccessDenied” result when trying to access the file publicly

---

### ✅ Phase 2 Complete!

At this point, I’ve fully simulated the insecure upload and verified that the **auto-remediation pipeline works from end to end**. The Lambda function successfully detected the violation and revoked the public permissions on its own.

Up next, I’ll explore **Phase 3: Improving Detection and Adding Notifications (SNS/Email)** to alert security teams whenever this kind of misconfiguration happens.

