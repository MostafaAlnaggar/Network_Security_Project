from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime
import ipaddress
import os
import shutil


# Define backup directory
BACKUP_DIR = "key_backups"


# Ensure backup directory exists
if not os.path.exists(BACKUP_DIR):
    os.makedirs(BACKUP_DIR)

# Backs up existing files to the backup directory with a timestamp.
def backup_existing_files(filenames):
    timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    for filename in filenames:
        if os.path.exists(filename):
            # Construct backup filename with timestamp
            basename = os.path.basename(filename)
            backup_filename = f"{basename}.{timestamp}.bak"
            backup_path = os.path.join(BACKUP_DIR, backup_filename)
            shutil.move(filename, backup_path)
            print(f"Backed up {filename} to {backup_path}.")

def generate_private_key(key_size=2048):
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )

def save_private_key(private_key, filename):
    with open(filename, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

def save_certificate(cert, filename):
    with open(filename, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

def get_public_key(private_key):
    public_key = private_key.public_key()
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem_public_key.decode('utf-8')

def generate_ca():
    # Generate CA's private key
    ca_key = generate_private_key(4096)
    save_private_key(ca_key, "ca.key")
    
    # Generate CA's self-signed certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MyCompany"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "IT"),
        x509.NameAttribute(NameOID.COMMON_NAME, "MyCompany CA"),
    ])
    
    ca_cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        ca_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        # CA certificate valid for 10 years
        datetime.datetime.utcnow() + datetime.timedelta(days=3650)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True,
    ).sign(ca_key, hashes.SHA256())
    
    save_certificate(ca_cert, "ca.pem")
    print("CA certificate and key generated.")
    print("CA Public Key:")
    print(get_public_key(ca_key))

def generate_certificate(subject_common_name, filename_prefix, ca_cert, ca_key, is_server=False):
    # Generate private key
    key = generate_private_key()
    save_private_key(key, f"{filename_prefix}.key")
    
    # Generate CSR
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MyCompany"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "IT"),
        x509.NameAttribute(NameOID.COMMON_NAME, subject_common_name),
    ])
    
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        subject
    ).sign(key, hashes.SHA256())
    
    # Define certificate validity
    valid_from = datetime.datetime.utcnow()
    valid_to = valid_from + datetime.timedelta(days=365)  # 1 year validity
    
    # Build certificate
    cert_builder = x509.CertificateBuilder().subject_name(
        csr.subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        csr.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        valid_from
    ).not_valid_after(
        valid_to
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    )
    
    # Add SANs
    san_list = []
    if is_server:
        # For server certificates, include DNS and IP
        san_list.extend([
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.IPv4Address("127.0.0.1"))
        ])
    else:
        # For client certificates, include only DNS or IP as needed
        # Here, we include IP for local testing
        san_list.append(x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")))
    
    cert_builder = cert_builder.add_extension(
        x509.SubjectAlternativeName(san_list),
        critical=False
    )
    
    cert = cert_builder.sign(private_key=ca_key, algorithm=hashes.SHA256())
    
    # Save certificate
    save_certificate(cert, f"{filename_prefix}.pem")
    print(f"{filename_prefix.capitalize()} certificate and key generated.")
    print(f"{filename_prefix.capitalize()} Public Key:")
    print(get_public_key(key))
    

def main():

    # Define the files to back up before generating new ones
    files_to_backup = ["ca.key", "ca.pem", "server.key", "server.pem", "client.key", "client.pem"]
    
    # Perform backup
    backup_existing_files(files_to_backup)

    # Generate CA
    generate_ca()
    
    # Load CA certificate and key
    with open("ca.pem", "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    
    with open("ca.key", "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)
    
    # Generate Server Certificate
    generate_certificate("localhost", "server", ca_cert, ca_key, is_server=True)
    
    # Generate Client Certificate
    generate_certificate("client", "client", ca_cert, ca_key, is_server=False)
    
    print("All certificates and keys generated successfully.")

if __name__ == "__main__":
    main()
