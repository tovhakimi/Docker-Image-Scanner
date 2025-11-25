import json
import os
import boto3
import subprocess
import psycopg2
from datetime import datetime
import time

sqs = boto3.client('sqs')
s3 = boto3.client('s3')

QUEUE_URL = os.environ.get('SQS_QUEUE_URL')
S3_BUCKET = os.environ.get('S3_BUCKET')
DB_HOST = os.environ.get('DB_HOST')
DB_NAME = os.environ.get('DB_NAME')
DB_USER = os.environ.get('DB_USER')
DB_PASSWORD = os.environ.get('DB_PASSWORD')

def get_db_connection():
    """Connect to PostgreSQL database"""
    return psycopg2.connect(
        host=DB_HOST,
        database=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD,
        connect_timeout=10,
        sslmode='require'
    )

def update_scan_status(scan_id, status, error_message=None):
    """Update scan status in database"""
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        if status == 'scanning':
            query = "UPDATE scan_jobs SET status = %s, started_at = NOW() WHERE id = %s"
            cursor.execute(query, (status, scan_id))
        elif status == 'completed':
            query = "UPDATE scan_jobs SET status = %s, completed_at = NOW() WHERE id = %s"
            cursor.execute(query, (status, scan_id))
        elif status == 'failed':
            query = "UPDATE scan_jobs SET status = %s, completed_at = NOW(), error_message = %s WHERE id = %s"
            cursor.execute(query, (status, error_message, scan_id))
        
        conn.commit()
        cursor.close()
        print(f"Updated scan {scan_id} status to: {status}")
    except Exception as e:
        print(f"Error updating status: {e}")
        if conn:
            conn.rollback()
    finally:
        if conn:
            conn.close()

def store_vulnerabilities(scan_id, vulnerabilities):
    """Store vulnerabilities in database"""
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        query = """
            INSERT INTO vulnerabilities 
            (scan_job_id, cve_id, severity, package_name, installed_version, fixed_version, title, description)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """
        
        count = 0
        for vuln in vulnerabilities:
            cursor.execute(query, (
                scan_id,
                vuln.get('VulnerabilityID'),
                vuln.get('Severity'),
                vuln.get('PkgName'),
                vuln.get('InstalledVersion'),
                vuln.get('FixedVersion'),
                vuln.get('Title'),
                vuln.get('Description')
            ))
            count += 1
        
        conn.commit()
        cursor.close()
        print(f"Stored {count} vulnerabilities for scan {scan_id}")
    except Exception as e:
        print(f"Error storing vulnerabilities: {e}")
        if conn:
            conn.rollback()
    finally:
        if conn:
            conn.close()

def scan_docker_image(image_name):
    """Run Trivy scan on Docker image"""
    print(f"Scanning Docker image: {image_name}")
    
    try:
        result = subprocess.run(
            ['trivy', 'image', '--format', 'json', '--quiet', image_name],
            capture_output=True,
            text=True,
            timeout=600
        )
        
        if result.returncode != 0:
            raise Exception(f"Trivy scan failed: {result.stderr}")
        
        scan_results = json.loads(result.stdout)
        
        vulnerabilities = []
        if 'Results' in scan_results:
            for result in scan_results['Results']:
                if 'Vulnerabilities' in result and result['Vulnerabilities']:
                    vulnerabilities.extend(result['Vulnerabilities'])
        
        print(f"Found {len(vulnerabilities)} vulnerabilities")
        return {
            'scan_results': scan_results,
            'vulnerabilities': vulnerabilities,
            'summary': {
                'total': len(vulnerabilities),
                'critical': sum(1 for v in vulnerabilities if v.get('Severity') == 'CRITICAL'),
                'high': sum(1 for v in vulnerabilities if v.get('Severity') == 'HIGH'),
                'medium': sum(1 for v in vulnerabilities if v.get('Severity') == 'MEDIUM'),
                'low': sum(1 for v in vulnerabilities if v.get('Severity') == 'LOW')
            }
        }
    except Exception as e:
        print(f"Scan error: {e}")
        raise

def process_message(message):
    """Process a single scan message"""
    try:
        body = json.loads(message['Body'])
        scan_id = body['scan_id']
        scan_type = body['type']
        target = body['target']
        receipt_handle = message['ReceiptHandle']
        
        print(f"\n{'='*60}")
        print(f"Processing scan: {scan_id}")
        print(f"Type: {scan_type}")
        print(f"Target: {target}")
        print(f"{'='*60}")
        
        update_scan_status(scan_id, 'scanning')
        
        if scan_type == 'docker-image':
            results = scan_docker_image(target)
        else:
            raise Exception(f"Unsupported scan type: {scan_type}")
        
        s3_key = f"scans/{scan_id}/results.json"
        s3.put_object(
            Bucket=S3_BUCKET,
            Key=s3_key,
            Body=json.dumps(results['scan_results'], indent=2),
            ContentType='application/json'
        )
        print(f"Uploaded results to S3: {s3_key}")
        
        if results['vulnerabilities']:
            store_vulnerabilities(scan_id, results['vulnerabilities'])
        
        update_scan_status(scan_id, 'completed')
        
        sqs.delete_message(
            QueueUrl=QUEUE_URL,
            ReceiptHandle=receipt_handle
        )
        print(f"Deleted message from SQS")
        print(f"Scan completed successfully!")
        print(f"Summary: {results['summary']}")
        
    except Exception as e:
        print(f"Error processing message: {e}")
        try:
            update_scan_status(scan_id, 'failed', str(e))
        except:
            pass

def main():
    """Main worker loop"""
    print("Scanner worker starting...")
    print(f"Queue URL: {QUEUE_URL}")
    print(f"S3 Bucket: {S3_BUCKET}")
    print(f"Database: {DB_HOST}")
    print("\nPolling for messages...\n")
    
    while True:
        try:
            response = sqs.receive_message(
                QueueUrl=QUEUE_URL,
                MaxNumberOfMessages=1,
                WaitTimeSeconds=20, 
                VisibilityTimeout=300 
            )
            
            if 'Messages' in response:
                for message in response['Messages']:
                    process_message(message)
            else:
                print("No messages. Waiting...")
            
        except KeyboardInterrupt:
            print("\nShutting down gracefully...")
            break
        except Exception as e:
            print(f"Worker error: {e}")
            time.sleep(10)

if __name__ == '__main__':
    main()
