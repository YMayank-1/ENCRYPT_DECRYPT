from google.cloud import bigquery


client = bigquery.Client()

def encrypt_table_data(project_id, dataset_id, table_id, columns_to_encrypt):
    #CREATING TABLE FOR STORING DEK
    keyset_table_sql = f"""
    CREATE TABLE `{project_id}.{dataset_id}.my_keysets` (
      id STRING,
      keyset BYTES
    );
    """
    client.query(keyset_table_sql).result()

    # CREATING WRAPPED DEK KEYSET
    keyset_insert_sql = f"""
    INSERT INTO `{project_id}.{dataset_id}.my_keysets` (id, keyset)
    SELECT
      "{table_id}",
      KEYS.NEW_WRAPPED_KEYSET (
        'gcp-kms://projects/{project_id}/locations/asia-northeast1/keyRings/my-test-keyring/cryptoKeys/my-test-key',
        'DETERMINISTIC_AEAD_AES_SIV_CMAC_256'
      );
    """
    client.query(keyset_insert_sql).result()

    # SELECTING A KEY FOR THE ENCRYPTION
    selected_keyset_query = f"""
    DECLARE selected_keyset BYTES;

    SET selected_keyset = (SELECT keyset FROM `{project_id}.{dataset_id}.my_keysets` WHERE id = "{table_id}");
    """
    client.query(selected_keyset_query).result()

    # ENCRYPTING THE DATA
    encrypt_query = f"""
    INSERT INTO `{project_id}.{dataset_id}.my_new_table` (id, encrypted_key, {', '.join(columns_to_encrypt)})
    SELECT
      id,
      selected_keyset,
      {', '.join([f"DETERMINISTIC_ENCRYPT (
          KEYS.KEYSET_CHAIN (
            'gcp-kms://projects/{project_id}/locations/asia-northeast1/keyRings/my-test-keyring/cryptoKeys/my-test-key',
            selected_keyset
          ),
          {col},
          ''
        ) AS {col}" for col in columns_to_encrypt])}
    FROM `{project_id}.{dataset_id}.{table_id}`;
    """
    client.query(encrypt_query).result()

# TEST 
# project_id = "your-project-id"
# dataset_id = "your-dataset-id"
# table_id = "your-table-id"
# columns_to_encrypt = ["column1", "column2", "column3"]

encrypt_table_data(project_id, dataset_id, table_id, columns_to_encrypt)
