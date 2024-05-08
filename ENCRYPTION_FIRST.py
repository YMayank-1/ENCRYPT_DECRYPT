from google.cloud import bigquery
from google.cloud import kms
from Crypto.Cipher import AES
from Crypto.Util import Padding
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import crypto.random
import os
import json
import base64


bq_client = bigquery.Client()


kms_client = kms.KeyManagementServiceClient()


symmetric_key = crypto.random.randomBytes(32)


def symmetric_encrypt(plaintext, key):
    iv = crypto.random.randomBytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(Padding.pad(plaintext.encode(), AES.block_size))
    return {"iv": iv, "encrypted_payload": base64.b64encode(encrypted).decode()}


async def encrypt_asymmetric(latest_key, plaintext_buffer):
   
    public_key = kms_client.get_public_key(name=latest_key)

    
    if public_key.name != latest_key or crc32c.crc32(public_key.pem.encode()) != public_key.pem_crc32c.value:
        raise ValueError('GetPublicKey: request corrupted in-transit')

    # Encrypt plaintext locally using the public key
    key = RSA.import_key(public_key.pem)
    cipher_rsa = PKCS1_OAEP.new(key)
    ciphertext = cipher_rsa.encrypt(plaintext_buffer.encode(), None)[0]
    return base64.b64encode(ciphertext).decode()

# Fetch latest key version from KMS
async def fetch_latest_key_version(project_id, location_id, key_ring_id, key_id):
    parent = kms_client.crypto_key_path(project_id, location_id, key_ring_id, key_id)
    versions = kms_client.list_crypto_key_versions(request={"parent": parent})
    latest_version = versions[versions.length - 1]  # Assuming versions are ordered by creation time
    latest_key = latest_version.name
    parts = latest_key.split('/')
    version_number = parts[-1]
    return {"latest_key": latest_key, "version_number": version_number}


def fetch_rows(project_id, dataset_id, table_id):
    table_ref = f"{project_id}.{dataset_id}.{table_id}"
    query = f"SELECT * FROM `{table_ref}`"
    query_job = bq_client.query(query)
    rows = query_job.result()
    return rows


async def main(project_id, dataset_id, table_id, key_project_id, key_location_id, key_ring_id, key_id, new_dataset_id, new_table_id, columns_to_encrypt):
    rows = fetch_rows(project_id, dataset_id, table_id)
    latest_key = await fetch_latest_key_version(key_project_id, key_location_id, key_ring_id, key_id)
    new_table_ref = f"{project_id}.{new_dataset_id}.{new_table_id}"

    for row in rows:
        encrypted_row = {}
        for key, value in row.items():
            if key in columns_to_encrypt:
                result = symmetric_encrypt(value, symmetric_key)
                encrypted_value = result["encrypted_payload"]
                iv = result["iv"]
                encrypted_row[key] = encrypted_value
                encrypted_row["iv"] = base64.b64encode(iv).decode()

        key_value = {"key": symmetric_key, "iv": iv}
        plaintext_buffer = json.dumps(key_value)

        encrypted_key = await encrypt_asymmetric(latest_key["latest_key"], plaintext_buffer)
        encrypted_row['encrypted_key'] = encrypted_key

        insert_data_into_table(new_table_ref, encrypted_row)



def insert_data_into_table(table_ref, data):
    table = bq_client.get_table(table_ref)
    errors = bq_client.insert_rows_json(table, [data])
    if errors:
        raise Exception(f"Error inserting rows: {errors}")



await main(project_id, dataset_id, table_id, key_project_id, key_location_id, key_ring_id, key_id, new_dataset_id, new_table_id, columns_to_encrypt)

