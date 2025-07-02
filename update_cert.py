import os
import json
import base64
import requests
from kubernetes import client, config
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning
from OpenSSL import crypto
import time
import dateutil.parser
from kubernetes.client.rest import ApiException
from datetime import datetime, timedelta, timezone

disable_warnings(InsecureRequestWarning)


def get_secret_data(secret_name, namespace):
    config.load_incluster_config()
    v1 = client.CoreV1Api()
    secret = v1.read_namespaced_secret(secret_name, namespace)
    cert = base64.b64decode(secret.data["tls.crt"]).decode()
    key = base64.b64decode(secret.data["tls.key"]).decode()
    return cert, key


def format_serial_for_redfish(serial_number: int) -> str:
    hex_str = format(serial_number, 'x')
    if len(hex_str) % 2:
        hex_str = '0' + hex_str
    return ':'.join(hex_str[i:i + 2].upper() for i in range(0, len(hex_str), 2))


def get_ilo_serial(ilo_host, username, password):
    url = f"https://{ilo_host}/redfish/v1/Managers/1/SecurityService/HttpsCert"
    r = requests.get(url, verify=False, auth=(username, password), timeout=10)
    r.raise_for_status()
    return r.json()["X509CertificateInformation"]["SerialNumber"].upper()


def update_ilo_cert(ilo_host, username, password, cert_bundle):
    url = f"https://{ilo_host}/redfish/v1/Managers/1/SecurityService/HttpsCert/Actions/HpeHttpsCert.ImportCertificate"
    headers = {"Content-Type": "application/json"}
    data = {"Certificate": cert_bundle}
    r = requests.post(url, json=data, headers=headers, verify=False, auth=(username, password), timeout=10)
    r.raise_for_status()
    print(f"Updated certificate on iLO: {ilo_host}")


def oneview_login(host, username, password):
    url = f"https://{host}/rest/login-sessions"
    headers = {"X-Api-Version": "7600"}
    data = {"userName": username, "password": password}
    r = requests.post(url, json=data, headers=headers, verify=False, timeout=10)
    r.raise_for_status()
    return r.json()["sessionID"]

def oneview_get_current_cert_info(host, session_id):
    url = f"https://{host}/rest/certificates/https"
    headers = {
        "X-Api-Version": "7600",
        "auth": session_id
    }
    r = requests.get(url, headers=headers, verify=False, timeout=10)
    r.raise_for_status()
    return r.json()

def oneview_cert_needs_replacement(ov_host, cert_info):
    valid_until = dateutil.parser.isoparse(cert_info["validUntil"])
    now = datetime.now(timezone.utc)
    delta = valid_until - now
    five_years = timedelta(days=365*5)
    thirty_days = timedelta(days=30)

    if delta > five_years:
        print(f"OneView cert on {ov_host} validUntil {valid_until} > 5 years: likely default cert, needs replacement.")
        return True
    if delta < thirty_days:
        print(f"OneView cert on {ov_host} validUntil {valid_until} < 30 days: cert nearing expiry, needs replacement.")
        return True
    print(f"OneView cert on {ov_host} validUntil {valid_until} is valid, no replacement needed.")
    return False

def oneview_request_csr(host, session_id, common_name, alt_names, country="US", locality="City", organization="Org", state="State"):
    url = f"https://{host}/rest/certificates/https/certificaterequest"
    headers = {
        "X-Api-Version": "7600",
        "auth": session_id,
        "Content-Type": "application/json"
    }
    data = {
        "commonName": common_name,
        "alternativeName": alt_names,
        "country": country,
        "locality": locality,
        "organization": organization,
        "state": state
    }
    r = requests.post(url, json=data, headers=headers, verify=False, timeout=10)
    r.raise_for_status()
    return base64.b64encode(r.json()["base64Data"].encode()).decode()

def create_certificate_request(api_instance, namespace, name, csr_pem_base64):
    body = {
        "apiVersion": "cert-manager.io/v1",
        "kind": "CertificateRequest",
        "metadata": {
            "name": name,
            "namespace": namespace,
        },
        "spec": {
            "request": csr_pem_base64,
            "usages": ["digital signature", "content commitment", "key encipherment", "server auth", "client auth"],
            "issuerRef": {
                "name": os.environ["ISSUER_REF_NAME"],
                "kind": os.environ.get("ISSUER_REF_KIND", "Issuer"),
            }}
    }
    try:
        api_instance.create_namespaced_custom_object("cert-manager.io", "v1", namespace, "certificaterequests", body)
    except ApiException as e:
        if e.status == 409:  # Already exists
            api_instance.delete_namespaced_custom_object("cert-manager.io", "v1", namespace, "certificaterequests", name)
            time.sleep(2)
            api_instance.create_namespaced_custom_object("cert-manager.io", "v1", namespace, "certificaterequests", body)
        else:
            raise

def wait_for_certificate(api_instance, namespace, name, timeout=60):
    start = time.time()
    while time.time() - start < timeout:
        status = api_instance.get_namespaced_custom_object_status("cert-manager.io", "v1", namespace, "certificaterequests", name).get("status", {})
        conditions = status.get("conditions", [])
        ready = any(
            cond["type"] == "Ready" and cond["status"] == "True"
            for cond in conditions
        )
        if ready and "certificate" in status:
            return status["certificate"]
        time.sleep(5)
    raise TimeoutError(f"Timed out waiting for CertificateRequest {name} to be issued")

def oneview_upload_cert(host, session_id, full_cert_pem):
    url = f"https://{host}/rest/certificates/https"
    headers = {
        "X-Api-Version": "7600",
        "auth": session_id,
        "Content-Type": "application/json"
    }
    decoded = base64.b64decode(full_cert_pem.encode()).decode()
    data = {"base64Data": decoded}
    r = requests.put(url, json=data, headers=headers, verify=False, timeout=10)
    r.raise_for_status()
    print(f"Updated certificate on OneView: {host}")

def main():
    config.load_incluster_config()
    namespace = os.environ["CERT_SECRET_NAMESPACE"]
    username = os.environ["ILO_USERNAME"]
    password = os.environ["ILO_PASSWORD"]

    # iLO processing
    ilo_map = dict(item.split("=", 1) for item in os.environ.get("ILO_CERT_MAP", "").split(",") if item)
    for ilo, secret in ilo_map.items():
        cert, key = get_secret_data(secret.strip(), namespace)
        x509 = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
        new_serial = format_serial_for_redfish(x509.get_serial_number())

        try:
            current_serial = get_ilo_serial(ilo, username, password)
            if current_serial != new_serial:
                print(f"iLO serial mismatch on {ilo}: {current_serial} != {new_serial}")
                update_ilo_cert(ilo, username, password, cert + "\n" + key)
            else:
                print(f"iLO certificate on {ilo} is up to date.")
        except Exception as e:
            print(f"Failed to update iLO {ilo}: {e}")

    # OneView processing
    oneview_map = dict(item.split("=", 1) for item in os.environ.get("ONEVIEW_CERT_MAP", "").split(",") if item)
    api_instance = client.CustomObjectsApi()

    for ov_host, host_name in oneview_map.items():
        try:
            session_id = oneview_login(ov_host, username, password)

            cert_info = oneview_get_current_cert_info(ov_host, session_id)

            if oneview_cert_needs_replacement(cert_info):
                # Build altNames from FQDN and IP
                fqdn = f"{host_name.strip()}.{os.environ.get('DNS_SUFFIX', 'example.com')}"
                alt_names = f"{ov_host},{fqdn}"

                # Request CSR from OneView
                csr_base64 = oneview_request_csr(
                    ov_host,
                    session_id,
                    common_name=fqdn,
                    alt_names=alt_names,
                    country=os.environ.get("CERT_COUNTRY", "US"),
                    locality=os.environ.get("CERT_LOCALITY", "City"),
                    organization=os.environ.get("CERT_ORGANIZATION", "Org"),
                    state=os.environ.get("CERT_STATE", "State"),
                )

                # Create Kubernetes CertificateRequest
                create_certificate_request(api_instance, namespace, host_name.strip(), csr_base64)

                # Wait for cert to be issued
                full_cert_pem = wait_for_certificate(api_instance, namespace, host_name.strip())

                # Upload issued cert chain to OneView
                oneview_upload_cert(ov_host, session_id, full_cert_pem)

            else:
                print(f"OneView certificate on {ov_host} is up to date.")
        except Exception as e:
            print(f"Failed to update OneView {ov_host}: {e}")
            raise

if __name__ == "__main__":
    main()
