# -------------------------------------------------------------------------
# This script was written to fix issues with the Nexpose Data
# Warehouse and the vulnerability_instance fields which,
# as of the date of this commit, are not properly tallied.
# This script runs a report (must already be configured), downloads,
# writes to the Data Warehouse fact_asset_vulnerability_instance
# table and then performs queries to update the fact_all,
# fact_vulnerability and fact_asset tables vulnerability_instance
# columns
# -------------------------------------------------------------------------

import base64
import collections
import csv
import io
import logging
import psycopg2
import rapid7vmconsole
import sys
import time

from cryptography.fernet import Fernet
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Suppress annoying self-signed cert warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def initialize_api(password):
    config = rapid7vmconsole.Configuration(name='Rapid7')
    config.username = 'apiuser'
    config.password = password
    config.host = 'https://itnexpose'
    config.verify_ssl = False
    config.assert_hostname = False
    config.proxy = None
    config.ssl_ca_cert = None
    config.connection_pool_maxsize = None
    config.cert_file = None
    config.key_file = None
    config.safe_chars_for_path_param = ''

    # Logging
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    logger.addHandler(ch)
    config.debug = False

    auth = "%s:%s" % (config.username, config.password)
    auth = base64.b64encode(auth.encode('ascii')).decode()
    client = rapid7vmconsole.ApiClient(configuration=config)
    client.default_headers['Authorization'] = "Basic %s" % auth

    return client

# Decrypt the api user password
def decrypt_password():
    cipher_suite = Fernet(key)

    with open('rapid7_pass.bin', 'rb') as file_object:
        for line in file_object:
            cipher_text = line
    plain_text  = cipher_suite.decrypt(cipher_text)
    return bytes(plain_text).decode("utf-8")

def run_report():
    # Create client
    password = decrypt_password()
    client = initialize_api(password)

    report_api = rapid7vmconsole.ReportApi(client)

    instance_id = (report_api.generate_report(id=4054)).id

    start_time = time.time()
    while(True):
        # If waiting more than two hours, exit
        if (time.time() - start_time > 7200):
            sys.exit()
        time.sleep(300) # Sleep 5 minutes
        report_status = report_api.get_report_instance(
            id=4054,
            instance=instance_id
        )
        print('Report Status: ' + report_status.status)
        # If complete, download
        if report_status.status == 'complete':
            report = report_api.download_report(
                id=4054,
                instance=instance_id
            ).split('\n')

            return report
        # If not complete and not running, exit
        elif(report_status.status != 'running'):
            sys.exit()

def write_all(vulns):
    print('Connecting...')
    conn = psycopg2.connect(

    )
    cursor = conn.cursor()

    # Remove all existing entries
    print('Dumping fact_asset_vulnerability_instance...')
    statement = 'DELETE FROM fact_asset_vulnerability_instance'
    cursor.execute(statement)
    conn.commit()

    # Get list of vulnerability_ids and nexpose_ids
    statement = ('SELECT nexpose_id, vulnerability_id FROM dim_vulnerability')
    cursor.execute(statement)
    vulnerabilities = cursor.fetchall()
    vuln_dict = dict(vulnerabilities)

    inserts = []

    print('Getting values to insert...')
    for vuln in vulns:
        # Skip header line
        if 'Asset ID' in vuln:
            continue
        try:
            vuln = vuln.split(',')
            # Verify string exploded correctly
            if (len(vuln) != 5):
                continue
            # Get vulnerability_id from nexpose_id
            vulnerability_id = vuln_dict[vuln[1]]
            inserts.append((
                vuln[0],
                str(vulnerability_id),
                vuln[2],
                vuln[3],
                vuln[4]
            ))

        except:
            print('Unexpected error: ', sys.exc_info()[0])
            print(vuln)

    # Create insert
    # Break into multiple parts to avoid memory issues...
    print('Inserting to fact_asset_vulnerability_instance...')
    inserts_a = inserts[0:3000000]
    inserts_b = inserts[3000000:]
    records_list_template = ','.join(['%s'] * len(inserts_a))
    statement = ('INSERT INTO fact_asset_vulnerability_instance '
        + '(asset_id, vulnerability_id, service, port, protocol) '
        + 'VALUES {}'
    ).format(records_list_template)

    cursor.execute(statement, inserts_a)
    conn.commit()

    records_list_template = ','.join(['%s'] * len(inserts_b))
    statement = ('INSERT INTO fact_asset_vulnerability_instance '
        + '(asset_id, vulnerability_id, service, port, protocol) '
        + 'VALUES {}'
    ).format(records_list_template)

    cursor.execute(statement, inserts_b)
    conn.commit()

    cursor.close()
    conn.close()

def get_all_table_records(table):
    conn = psycopg2.connect(

    )
    cursor = conn.cursor()

    statement = 'SELECT * FROM ' + table
    cursor.execute(statement)
    records = cursor.fetchall()

    cursor.close()
    conn.close()

    return records

# Thanks to luke on GitHub for this function to do bulk updates
# https://gist.github.com/luke/5697511
def data2csv(data):
    si = io.StringIO()
    cw = csv.writer(si, delimiter='\t',lineterminator="\n")
    for row in data:
        r = [ (x is None and '\n' or x) for x in row]
        cw.writerow(r)
    si.seek(0)
    return si # .getvalue()

def upsert(cursor, table_name, selector_fields, setter_fields, data):

    csv_data = data2csv(data)

    sql_template = """
        WITH updates AS (
            UPDATE %(target)s t
                SET %(set)s
            FROM source s
            WHERE %(where_t_pk_eq_s_pk)s
            RETURNING %(s_pk)s
        )
        INSERT INTO %(target)s (%(columns)s)
            SELECT %(source_columns)s
            FROM source s LEFT JOIN updates t USING(%(pk)s)
            WHERE %(where_t_pk_is_null)s
    """
    statement = sql_template % dict(
        target = table_name,
        set = ',\n'.join(["%s = s.%s" % (x,x) for x in setter_fields]),
        where_t_pk_eq_s_pk = ' AND '.join(["t.%s = s.%s" % (x,x) for x in selector_fields]),
        s_pk = ','.join(["s.%s" % x for x in selector_fields]),
        columns = ','.join([x for x in selector_fields+setter_fields]),
        source_columns = ','.join(['s.%s' % x for x in selector_fields+setter_fields]),
        pk = ','.join(selector_fields),
        where_t_pk_is_null = ' AND '.join(["t.%s IS NULL" % x for x in selector_fields]),
        t_pk = ','.join(["t.%s" % x for x in selector_fields]))

    # with cursor as cur:
    cur = cursor
    cur.execute('CREATE TEMP TABLE source(LIKE %s INCLUDING ALL) ON COMMIT DROP;' % table_name);
    cur.copy_from(csv_data, 'source', columns=selector_fields+setter_fields)
    cur.execute(statement)
    cur.execute('DROP TABLE source')
    csv_data.close()

def update_fact_vulnerability(vuln_instance_records):
    print('Updating fact_vulnerability...')
    fv_records = get_all_table_records('fact_vulnerability')
    counts = collections.Counter([b for (a,b,c,d,e,f,g,h,i) in vuln_instance_records])

    data = []

    for record in fv_records:
        data.append((record[0], counts[record[0]]))

    conn = psycopg2.connect(
    )
    cursor = conn.cursor()
    upsert(cursor, 'fact_vulnerability', ['vulnerability_id'], ['vulnerability_instances'], data)
    conn.commit()
    cursor.close()
    conn.close()

def update_fact_all(vuln_instance_records):
    print('Updateing fact_all...')

    conn = psycopg2.connect(

    )
    cursor = conn.cursor()

    statement = (
        'UPDATE fact_all SET vulnerability_instances = '
        + str(len(vuln_instance_records))
    )

    cursor.execute(statement)
    conn.commit()
    cursor.close()
    conn.close()

def update_fact_asset(vuln_instance_records):
    print('Updating fact_asset...')

    fa_records = get_all_table_records('fact_asset')
    counts = collections.Counter([a for (a,b,c,d,e,f,g,h,i) in vuln_instance_records])

    data = []

    for record in fa_records:
        data.append((record[0], counts[record[0]]))

    conn = psycopg2.connect(

    )
    cursor = conn.cursor()
    upsert(cursor, 'fact_asset', ['asset_id'], ['vulnerability_instances'], data)
    conn.commit()
    cursor.close()
    conn.close()

def update_fact_asset_group(vuln_instance_records):
    return

def update_fact_site(vuln_instance_records):
    return

def update_fact_asset_vulnerability_finding(vuln_instance_records):
    return

def update_fact_asset_vulnerability_finding_remediation(vuln_instance_records):
    return

def main():
    # Write table of vulnerability instances
    vulns = run_report()
    write_all(vulns)

    vuln_instance_records = get_all_table_records('fact_asset_vulnerability_instance')

    # Update all reference counts
    update_fact_vulnerability(vuln_instance_records)
    update_fact_all(vuln_instance_records)
    update_fact_asset(vuln_instance_records)
    #update_fact_asset_group(vuln_instance_records)
    #update_fact_site(vuln_instance_records)
    #update_fact_asset_vulnerability_finding(vuln_instance_records)
    #update_fact_asset_vulnerability_finding_remediation(vuln_instance_records)

if __name__ == '__main__':
    main()
