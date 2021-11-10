import os

import boto3
import botocore

from lexie_cloud.extensions import logger

S3_BUCKET_NAME = "lexie_cloud_data"
CONFIG_FILE = 'config.json'

def load_config_from_s3(): # pragma: nocover
    """Loads our tiny db from AWS S3"""
    bucket_name = S3_BUCKET_NAME
    s3client = boto3.resource('s3')
    try:
        s3client.Bucket(bucket_name).download_file(CONFIG_FILE, CONFIG_FILE)
        logger.info('Database loaded from S3')
    except botocore.exceptions.ClientError as e: # pylint: disable=invalid-name
        if e.response['Error']['Code'] == "404":
            logger.warning("Database file not found in S3, starting with empty one.")
        else:
            logger.warning('Found a local database file, using that.')
            if not os.path.exists(CONFIG_FILE):
                raise
    except botocore.exceptions.NoCredentialsError:
        if not os.path.exists(CONFIG_FILE):
            raise
