import json
import os
import uuid
import boto3
import psycopg2
from datetime import datetime

# Initialize AWS clients
sqs = boto3.client('sqs')

# Environment variables
QUEUE_URL = os.environ.get('SQS_QUEUE_URL', '')
DB_HOST = os.environ.get('DB_HOST', '')
DB_NAME = os.environ.get('DB_NAME', '')
DB_USER = os.environ.get('DB_USER', '')
DB_PASSWORD = os.environ.get('DB_PASSWORD', '')

def get_db_connection():
    """Create database connection"""
    try:
        conn = psycopg2.connect(
            host=DB_HOST,
            database=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD,
            connect_timeout=5,
            sslmode='require'
        )
        return conn
    except Exception as e:
        print(f"Database connection error: {str(e)}")
        raise

def create_scan_record(scan_id, scan_type, target):
    """Create scan record in database"""
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        query = """
            INSERT INTO scan_jobs (id, scan_type, target, status, created_at)
            VALUES (%s, %s, %s, %s, NOW())
        """
        
        cursor.execute(query, (scan_id, scan_type, target, 'queued'))
        conn.commit()
        cursor.close()
        
        print(f"Created scan record in database: {scan_id}")
        
    except Exception as e:
        print(f"Error creating scan record: {str(e)}")
        if conn:
            conn.rollback()
        raise
    finally:
        if conn:
            conn.close()

def lambda_handler(event, context):
    """
    Receives scan requests, stores in DB, and queues them in SQS
    """
    
    try:
        print(f"Received event: {json.dumps(event)}")
        
        # Parse request body
        if 'body' in event:
            body = json.loads(event['body'])
        else:
            body = event  # For testing
        
        print(f"Parsed body: {json.dumps(body)}")
        
        # Validate required fields
        if 'type' not in body or 'target' not in body:
            return {
                'statusCode': 400,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({
                    'error': 'Missing required fields: type and target'
                })
            }
        
        scan_type = body['type']
        target = body['target']
        
        # Validate scan type
        if scan_type not in ['docker-image', 'web-url']:
            return {
                'statusCode': 400,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({
                    'error': 'Invalid scan type. Must be docker-image or web-url'
                })
            }
        
        # Validate target format
        if scan_type == 'docker-image':
            if ':' not in target and '@' not in target:
                target = f"{target}:latest"
        
        # Generate unique scan ID
        scan_id = str(uuid.uuid4())
        print(f"Generated scan_id: {scan_id}")
        
        # Create database record
        create_scan_record(scan_id, scan_type, target)
        
        # Send message to SQS
        message_body = {
            'scan_id': scan_id,
            'type': scan_type,
            'target': target,
            'created_at': datetime.utcnow().isoformat()
        }
        
        print(f"Sending message to SQS: {json.dumps(message_body)}")
        
        response = sqs.send_message(
            QueueUrl=QUEUE_URL,
            MessageBody=json.dumps(message_body),
            MessageAttributes={
                'scan_type': {
                    'StringValue': scan_type,
                    'DataType': 'String'
                }
            }
        )
        
        message_id = response.get('MessageId', 'unknown')
        print(f"Message sent to SQS. MessageId: {message_id}")
        
        # Return success response
        return {
            'statusCode': 202,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            'body': json.dumps({
                'scan_id': scan_id,
                'status': 'queued',
                'message': 'Scan request queued successfully',
                'type': scan_type,
                'target': target
            })
        }
        
    except Exception as e:
        import traceback
        error_trace = traceback.format_exc()
        print(f"Error: {str(e)}")
        print(f"Traceback: {error_trace}")
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({
                'error': 'Internal server error',
                'details': str(e)
            })
        }
