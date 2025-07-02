import os
import json
import base64
import requests
from kubernetes import client, config
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning
from OpenSSL import crypto

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


def get_oneview_serial(host, session_id):
    url = f"https://{host}/rest/certificates/https"
    headers = {
        "X-Api-Version": "7600",
        "auth": session_id
    }
    r = requests.get(url, headers=headers, verify=False, timeout=10)
    r.raise_for_status()
    return r.json()["serialNumber"].replace(":", "").upper()


def update_oneview_cert(host, session_id, cert, key):
    url = f"https://{host}/rest/certificates/https"
    headers = {
        "X-Api-Version": "7600",
        "auth": session_id,
        "Content-Type": "application/json"
    }
    cert_pem = f"{cert}\n{key}".encode()
    encoded = base64.b64encode(cert_pem).decode()
    data = {
        "type": "WebServerCert",
        "base64Data": encoded
    }
    r = requests.put(url, json=data, headers=headers, verify=False, timeout=10)
    r.raise_for_status()
    print(f"Updated certificate on OneView: {host}")


def process_devices(device_map, updater_fn, checker_fn, cert_formatter):
    username = os.environ["ILO_USERNAME"]
    password = os.environ["ILO_PASSWORD"]
    namespace = os.environ["CERT_SECRET_NAMESPACE"]

    for host, secret_name in device_map.items():
        cert, key = get_secret_data(secret_name.strip(), namespace)
        x509 = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
        formatted_serial = cert_formatter(x509.get_serial_number())

        try:
            current_serial = checker_fn(host, username, password)
            if current_serial.replace(":", "").upper() != formatted_serial.replace(":", "").upper():
                print(f"Serial mismatch on {host}: {current_serial} != {formatted_serial}")
                updater_fn(host, username, password, cert, key)
            else:
                print(f"Certificate on {host} is up to date.")
        except Exception as e:
            print(f"Failed to update {host}: {e}")


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
    for ov, secret in oneview_map.items():
        try:
            session_id = oneview_login(ov, username, password)
            cert, key = get_secret_data(secret.strip(), namespace)
            x509 = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
            new_serial = format(x509.get_serial_number(), 'x').upper().lstrip("0")
            current_serial = get_oneview_serial(ov, session_id).lstrip("0")

            if current_serial != new_serial:
                print(f"OneView serial mismatch on {ov}: {current_serial} != {new_serial}")
                update_oneview_cert(ov, session_id, cert, key)
            else:
                print(f"OneView certificate on {ov} is up to date.")
        except Exception as e:
            print(f"Failed to update OneView {ov}: {e}")


if __name__ == "__main__":
    main()
