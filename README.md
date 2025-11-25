# AWS Vulnerability Scanner as a Service

A production-grade, cloud-native vulnerability scanning platform built on AWS that automatically detects security vulnerabilities in Docker images using serverless architecture and containerized workers.

## Project Overview

This project demonstrates enterprise-level cloud architecture patterns including:
- Serverless API with AWS Lambda and API Gateway
- Asynchronous job processing with SQS
- Containerized workers on ECS Fargate
- Secure VPC networking with public/private subnet isolation
- PostgreSQL RDS for relational data
- S3 for object storage
- Comprehensive security controls (IAM, encryption, network isolation)

## Architecture

### High-Level Design
```
┌─────────────────────────────────────────────────────────────┐
│                         Internet                             │
└────────────────────┬────────────────────────────────────────┘
                     │
         ┌───────────▼──────────┐
         │    API Gateway       │  HTTPS REST API
         │  (POST /scans)       │
         └───────────┬──────────┘
                     │
         ┌───────────▼──────────┐
         │  Lambda Function     │  Serverless compute
         │  (Submit Scan)       │
         └───────────┬──────────┘
                     │
         ┌───────────▼──────────┐
         │     RDS PostgreSQL   │  Scan metadata
         │  + SQS Queue         │  Job queue
         └───────────┬──────────┘
                     │
         ┌───────────▼──────────┐
         │  ECS Fargate         │  Container workers
         │  (Trivy Scanner)     │
         └───────────┬──────────┘
                     │
         ┌───────────▼──────────┐
         │  S3 + RDS            │  Results storage
         │  (Reports + CVEs)    │
         └──────────────────────┘
```

### Network Architecture

- **VPC**: Isolated network (`10.0.0.0/16`)
- **Public Subnets**: API Gateway, NAT Gateway, Bastion Host
- **Private Subnets**: Lambda, ECS, RDS (no direct internet access)
- **Security Groups**: Least-privilege firewall rules
- **NAT Gateway**: Outbound internet for private resources

## Features

- **RESTful API** for scan submission and result retrieval
- **Asynchronous Processing** with SQS message queue
- **Containerized Scanners** using Docker and ECS Fargate
- **CVE Detection** powered by Trivy open-source scanner
- **Fault Tolerance** with Dead Letter Queue and automatic retries
- **Security First**: VPC isolation, encryption at rest/transit, IAM roles
- **Scalable**: Serverless API, auto-scaling workers
- **Observable**: CloudWatch logs and metrics

## API Documentation

### Submit Scan

**Endpoint:** `POST /scans`

**Request:**
```json
{
  "type": "docker-image",
  "target": "nginx:latest"
}
```

**Response:**
```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "queued",
  "message": "Scan request queued successfully",
  "type": "docker-image",
  "target": "nginx:latest"
}
```

**Status Codes:**
- `202 Accepted` - Scan queued successfully
- `400 Bad Request` - Invalid input
- `500 Internal Server Error` - Server error

### Get Scan Results

**Endpoint:** `GET /scans/{scan_id}`

**Response:**
```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "type": "docker-image",
  "target": "nginx:latest",
  "status": "completed",
  "created_at": "2024-11-24T10:00:00Z",
  "completed_at": "2024-11-24T10:05:23Z",
  "summary": {
    "critical": 2,
    "high": 5,
    "medium": 8,
    "low": 12,
    "total": 27
  },
  "vulnerabilities": [
    {
      "cve_id": "CVE-2024-1234",
      "severity": "CRITICAL",
      "package_name": "openssl",
      "installed_version": "3.0.8",
      "fixed_version": "3.0.9",
      "title": "Buffer overflow in OpenSSL",
      "description": "A buffer overflow vulnerability..."
    }
  ]
}
```

**Scan Status Values:**
- `queued` - Scan submitted, waiting for processing
- `scanning` - Currently being scanned
- `completed` - Scan finished successfully
- `failed` - Scan encountered an error

## Technology Stack

### AWS Services
- **Lambda** - Serverless compute for API handlers
- **API Gateway** - REST API management and routing
- **ECS Fargate** - Serverless container orchestration
- **RDS PostgreSQL** - Relational database for metadata
- **S3** - Object storage for scan reports
- **SQS** - Message queue for async processing
- **VPC** - Network isolation and security
- **IAM** - Identity and access management
- **CloudWatch** - Logging and monitoring
- **ECR** - Container registry

### Tools & Libraries
- **Python 3.12** - Lambda runtime and scanner script
- **Trivy** - Open-source vulnerability scanner
- **Docker** - Container packaging
- **psycopg2** - PostgreSQL driver
- **boto3** - AWS SDK for Python

## Project Structure
```
aws-vulnerability-scanner/
├── lambda/
│   ├── submit-scan/
│   │   └── lambda_function.py       # Submit scan endpoint
│   └── get-results/
│       └── lambda_function.py       # Get results endpoint
├── scanner/
│   ├── Dockerfile                    # Scanner container definition
│   └── scanner.py                    # Worker script (polls SQS, runs Trivy)
├── database/
│   └── schema.sql                    # PostgreSQL database schema
├── iam/
│   └── policies.json                 # IAM policies for Lambda
├── docs/
│   └── architecture-diagram.png      # Architecture diagram
├── .gitignore
└── README.md
```

## Security Features

### Network Security
- **VPC Isolation**: All resources in private network
- **Private Subnets**: Database and workers not internet-accessible
- **Security Groups**: Least-privilege firewall rules
- **NAT Gateway**: Controlled outbound internet access

### Data Security
- **Encryption at Rest**: RDS and S3 use AWS-managed encryption
- **Encryption in Transit**: TLS 1.3 for all API communication
- **IAM Roles**: No hardcoded credentials, temporary credentials only
- **Secrets Manager**: Database credentials stored securely (optional)

### Application Security
- **Input Validation**: All user inputs validated before processing
- **Rate Limiting**: API Gateway throttling to prevent abuse
- **Dead Letter Queue**: Failed jobs isolated for investigation
- **Audit Logging**: All actions logged to CloudWatch

## Getting Started

### Prerequisites
- AWS Account with appropriate permissions
- AWS CLI configured (`aws configure`)
- Docker installed locally
- Python 3.12+

### Deployment Steps

#### 1. Set Up Infrastructure

**Create VPC:**
```bash
# Create VPC with CIDR 10.0.0.0/16
# Create 2 public subnets, 2 private subnets
# Create Internet Gateway, NAT Gateway
# Configure route tables
```

**Create Security Groups:**
```bash
# bastion-sg: SSH access
# lambda-sg: Outbound only
# rds-sg: PostgreSQL from Lambda/ECS only
# ecs-sg: Outbound only
```

#### 2. Set Up Database
```bash
# Create RDS PostgreSQL instance
aws rds create-db-instance \
  --db-instance-identifier vuln-scanner-db \
  --db-instance-class db.t3.micro \
  --engine postgres \
  --master-username scanner_admin \
  --master-user-password YOUR_PASSWORD \
  --allocated-storage 20

# Run schema
psql -h YOUR_RDS_ENDPOINT -U scanner_admin -d vulnerability_scanner -f database/schema.sql
```

#### 3. Deploy Lambda Functions
```bash
# Create execution role
aws iam create-role --role-name VulnScannerLambdaRole ...

# Deploy submit-scan function
cd lambda/submit-scan
zip function.zip lambda_function.py
aws lambda create-function \
  --function-name vuln-scanner-submit \
  --runtime python3.12 \
  --role arn:aws:iam::ACCOUNT:role/VulnScannerLambdaRole \
  --handler lambda_function.lambda_handler \
  --zip-file fileb://function.zip
```

#### 4. Set Up API Gateway
```bash
# Create REST API
aws apigateway create-rest-api --name vulnerability-scanner-api

# Create resources and methods
# Deploy to prod stage
```

#### 5. Build and Deploy Scanner
```bash
# Build Docker image
cd scanner
docker build -t vuln-scanner .

# Push to ECR
aws ecr create-repository --repository-name vuln-scanner
docker tag vuln-scanner:latest ACCOUNT.dkr.ecr.REGION.amazonaws.com/vuln-scanner:latest
docker push ACCOUNT.dkr.ecr.REGION.amazonaws.com/vuln-scanner:latest

# Create ECS task definition and service
aws ecs create-cluster --cluster-name vuln-scanner-cluster
aws ecs register-task-definition --cli-input-json file://task-definition.json
aws ecs create-service --cluster vuln-scanner-cluster ...
```

## Cost Estimation

### Monthly Costs (Approximate)

| Service | Usage | Cost |
|---------|-------|------|
| Lambda | 1000 requests, 128MB, 3s avg | $0.00 (Free tier) |
| API Gateway | 1000 requests | $0.00 (Free tier) |
| RDS (db.t3.micro) | 720 hours | ~$13 |
| NAT Gateway | 730 hours + data | ~$33 |
| ECS Fargate | 1 task, 1vCPU, 2GB | ~$30 |
| S3 | 10GB storage, 1000 requests | ~$0.50 |
| SQS | 10,000 requests | $0.00 (Free tier) |
| **Total** | | **~$76/month** |

### Cost Optimization Tips
- Stop RDS when not in use (save $13/month)
- Use VPC endpoints instead of NAT Gateway (save $33/month)
- Scale ECS tasks to zero when idle (save $30/month)
- Implement S3 lifecycle policies (save on storage)

## Testing

### Local Testing
```bash
# Test Lambda function locally
python lambda/submit-scan/lambda_function.py

# Test scanner container
docker run -e SQS_QUEUE_URL=... -e DB_HOST=... vuln-scanner
```

### API Testing
```bash
# Submit scan
curl -X POST https://YOUR_API_URL/prod/scans \
  -H "Content-Type: application/json" \
  -d '{"type": "docker-image", "target": "nginx:latest"}'

# Get results
curl https://YOUR_API_URL/prod/scans/SCAN_ID
```

## Monitoring & Observability

### CloudWatch Metrics
- Lambda invocations, errors, duration
- API Gateway requests, latency, 4xx/5xx errors
- SQS queue depth, message age
- ECS CPU/memory utilization

### CloudWatch Logs
- Lambda execution logs
- ECS container logs
- API Gateway access logs

### Alarms
- DLQ messages > 0 (failed scans)
- API Gateway 5xx errors > threshold
- Lambda errors > threshold
- SQS queue depth > threshold

## CI/CD Pipeline (Future Enhancement)
```yaml
# GitHub Actions workflow example
name: Deploy
on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Deploy Lambda
        run: |
          zip function.zip lambda_function.py
          aws lambda update-function-code ...
      - name: Build and push Docker
        run: |
          docker build -t vuln-scanner .
          docker push ...
```

## 🐛 Known Issues & Limitations

1. **NAT Gateway Cost**: Expensive for hobby projects (~$33/month)
   - *Mitigation*: Use VPC endpoints or public RDS (less secure)

2. **Cold Start Latency**: Lambda in VPC has 1-2s cold start
   - *Mitigation*: Use provisioned concurrency (costs more)

3. **Scan Timeout**: Very large images may timeout
   - *Mitigation*: Increase ECS task timeout, use spot instances

4. **No Authentication**: API is public (demo only)
   - *Mitigation*: Add API keys, Cognito, or IAM auth

## Learning Outcomes

This project demonstrates proficiency in:
- **AWS Cloud Architecture** - VPC, subnets, security groups, IAM
- **Serverless Computing** - Lambda, API Gateway, event-driven design
- **Container Orchestration** - Docker, ECS, Fargate
- **Async Processing** - SQS queues, message-driven architecture
- **Database Design** - PostgreSQL schema, relationships, indexing
- **Security Best Practices** - Encryption, least privilege, network isolation
- **RESTful API Design** - HTTP methods, status codes, resource modeling
- **DevOps Practices** - Infrastructure as code, monitoring, logging

## References

- [AWS Lambda Best Practices](https://docs.aws.amazon.com/lambda/latest/dg/best-practices.html)
- [Trivy Documentation](https://aquasecurity.github.io/trivy/)
- [AWS Well-Architected Framework](https://aws.amazon.com/architecture/well-architected/)
- [Twelve-Factor App Methodology](https://12factor.net/)

## License

MIT License - See LICENSE file for details

## Author

**Your Name**
- GitHub: [@yourusername](https://github.com/yourusername)
- LinkedIn: [Your Profile](https://linkedin.com/in/yourprofile)
- Email: your.email@example.com

## Acknowledgments

- Aqua Security for Trivy scanner
- AWS documentation and examples
- Open-source community

---

**Note**: This is a learning project demonstrating cloud architecture patterns. For production use, additional hardening, monitoring, and compliance controls would be required.
