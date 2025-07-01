import os
import json
import requests
from kubernetes import client, config
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning
from OpenSSL import crypto
import base64

disable_warnings(InsecureRequestWarning)


def get_secret_data(secret_name, namespace):
    config.load_incluster_config()
    v1 = client.CoreV1Api()
    secret = v1.read_namespaced_secret(secret_name, namespace)
    cert = base64.b64decode(secret.data["tls.crt"]).decode()
    key = base64.b64decode(secret.data["tls.key"]).decode()
    return cert, key


def get_cert_serial(ilo_host, username, password):
    url = f"https://{ilo_host}/redfish/v1/Managers/1/SecurityService/HttpsCert"
    r = requests.get(url, verify=False, auth=(username, password), timeout=10)
    r.raise_for_status()
    return r.json()["X509CertificateInformation"]["SerialNumber"]


def update_ilo_cert(ilo_host, username, password, cert_bundle):
    url = f"https://{ilo_host}/redfish/v1/Managers/1/SecurityService/HttpsCert/Actions/HpeHttpsCert.ImportCertificate"
    headers = {"Content-Type": "application/json"}
    data = {"Certificate": cert_bundle}
    r = requests.post(url, json=data, headers=headers, verify=False, auth=(username, password), timeout=10)
    r.raise_for_status()
    print(f"Updated certificate on {ilo_host}")

def main():
    ilo_map = os.environ["ILO_CERT_MAP"]
    username = os.environ["ILO_USERNAME"]
    password = os.environ["ILO_PASSWORD"]
    namespace = os.environ["CERT_SECRET_NAMESPACE"]

    config_map = dict(item.split("=", 1) for item in ilo_map.split(","))
    config.load_incluster_config()

    for ilo, secret_name in config_map.items():
        cert, key = get_secret_data(secret_name.strip(), namespace)
        cert_bundle = cert + "\n" + key
        x509 = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
        new_serial = format(x509.get_serial_number(), 'x').upper()
        current_serial = get_cert_serial(ilo, username, password).replace(":", "").upper()

        if current_serial != new_serial:
            print(f"Serial mismatch for {ilo}: {current_serial} != {new_serial}")
            update_ilo_cert(ilo, username, password, cert_bundle)
        else:
            print(f"Certificate on {ilo} is up to date.")

if __name__ == "__main__":
    main()
