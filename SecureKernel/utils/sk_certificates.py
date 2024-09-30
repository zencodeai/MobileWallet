# Import required libraries
import datetime
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend

# Generate attributes
def generate_attributes(cn: str) -> list:
    return [
        x509.NameAttribute(NameOID.COUNTRY_NAME, u'CA'),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u'ON'),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u'Ottawa'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'Fintech Inc.'),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, u'fintech-inc.ca'),
    ]

# Generate a self-signed P-256 certificate as root of a local certification authority
def generate_root_ca_cert(cn: str = 'CA-FINTECH-INC-ROOT', fileprefix: str = './data/ca_fintech_inc_root') -> None:
    # Generate a private key for the root CA
    root_ca_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

    # Generate a self-signed certificate for the root CA
    issuer = x509.Name(generate_attributes(cn))
    subject = x509.Name(generate_attributes(cn))

    root_ca_cert = x509.CertificateBuilder().subject_name(
        x509.Name(subject)).issuer_name(
        x509.Name(issuer)).not_valid_before(
        datetime.datetime.utcnow()).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=3650)).serial_number(
        x509.random_serial_number()).public_key(root_ca_key.public_key()).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True, ).sign(root_ca_key, hashes.SHA256(),
                                                                                 default_backend())

    # Write the root CA certificate to a file
    with open(f'{fileprefix}_cert.der', 'wb') as f:
        f.write(root_ca_cert.public_bytes(serialization.Encoding.DER))

    # Write the root CA private key to a file
    with open(f'{fileprefix}_key.der', 'wb') as f:
        f.write(root_ca_key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()))

# Generate an intermediate P-256 certificate signed by the root CA
def generate_intermediate_cert(name: str, fileprefix: str = './data/ca_fintech_inc_', rootprefix: str = './data/ca_fintech_inc_root') -> None:
    # cn
    cn = f'CA-FINTECH-INC-{name.upper()}'

    # File prefix
    fileprefix = f'{fileprefix}{name.lower()}'
    
    # Read the root CA certificate from a file
    with open(f'{rootprefix}_cert.der', 'rb') as f:
        root_ca_cert = x509.load_der_x509_certificate(f.read(), default_backend())

    # Read the root CA private key from a file
    with open(f'{rootprefix}_key.der', 'rb') as f:
        root_ca_key = serialization.load_der_private_key(f.read(), password=None, backend=default_backend())

    # Generate a private key for the intermediate CA
    intermediate_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

    # Generate a certificate signing request for the intermediate CA
    intermediate_csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name(
        generate_attributes(cn)
    )).add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True, ).sign(
        intermediate_key, hashes.SHA256(), default_backend())

    # Generate a certificate signed by the root CA for the intermediate CA
    intermediate_cert = x509.CertificateBuilder().subject_name(x509.Name(
        generate_attributes(cn)
    )).issuer_name(root_ca_cert.subject).not_valid_before(datetime.datetime.utcnow()).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=3650)).serial_number(
        x509.random_serial_number()).public_key(intermediate_csr.public_key()).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True, ).sign(root_ca_key, hashes.SHA256(),
                                                                                 default_backend())

    # Write the intermediate CA certificate to a file
    with open(f'{fileprefix}_cert.der', 'wb') as f:
        f.write(intermediate_cert.public_bytes(serialization.Encoding.DER))

    # Write the intermediate CA private key to a file
    with open(f'{fileprefix}_key.der', 'wb') as f:
        f.write(intermediate_key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                                               serialization.NoEncryption()))

# Generate a certificate revocation list signed by the root CA
def generate_crl(name: str, fileprefix: str = './data/ca_fintech_inc_', rootprefix: str = './data/ca_fintech_inc_root') -> None:

    # Create a certificate revocation list
    crl_builder = x509.CertificateRevocationListBuilder()
    crl_builder = crl_builder.issuer_name(x509.Name(generate_attributes('CA-FINTECH-INC-ROOT')))
    crl_builder = crl_builder.last_update(datetime.datetime.utcnow())
    crl_builder = crl_builder.next_update(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
    crl_builder = crl_builder.add_extension(x509.CRLDistributionPoints([
        x509.DistributionPoint([x509.UniformResourceIdentifier('http://fintech-inc.ca/crl/ca_fintech_inc_root.crl')],
                               relative_name=None, reasons=None, crl_issuer=None)
    ]), critical=False)
    crl_builder = crl_builder.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
        x509.load_der_x509_certificate(open(f'{rootprefix}_cert.der', 'rb').read(), default_backend()).public_key()),
        critical=False)
    crl_builder = crl_builder.add_extension(x509.AuthorityInformationAccess([
        x509.AccessDescription(x509.oid.AuthorityInformationAccessOID.CA_ISSUERS,
                               x509.UniformResourceIdentifier('http://fintech-inc.ca/cert/ca_fintech_inc_root_cert.der'))
    ]), critical=False)
    crl_builder = crl_builder.add_extension(x509.CRLNumber(1), critical=False)
    crl_builder = crl_builder.add_extension(x509.DeltaCRLIndicator(1), critical=False)
    crl_builder = crl_builder.add_extension(x509.IssuingDistributionPoint(
        full_name=None, relative_name=None, only_contains_user_certs=True, only_contains_ca_certs=False,
        only_some_reasons=None, indirect_crl=False, only_contains_attribute_certs=False), critical=False)
    crl_builder = crl_builder.add_extension(x509.FreshestCRL([x509.DistributionPoint([
        x509.UniformResourceIdentifier('http://fintech-inc.ca/crl/ca_fintech_inc_root.crl')], relative_name=None,
        reasons=None, crl_issuer=None)]), critical=False)
    crl_builder = crl_builder.add_extension(x509.IssuerAlternativeName([x509.UniformResourceIdentifier(
        'http://fintech-inc.ca/cert/ca_fintech_inc_root_cert.der')]), critical=False)
    
    # Read the root CA private key from a file
    with open(f'{rootprefix}_key.der', 'rb') as f:
        root_ca_key = serialization.load_der_private_key(f.read(), password=None, backend=default_backend())

    # Sign the certificate revocation list
    crl = crl_builder.sign(root_ca_key, hashes.SHA256(), default_backend())

    # Write the certificate revocation list to a file
    with open(f'{fileprefix}{name.lower()}_crl.der', 'wb') as f:
        f.write(crl.public_bytes(serialization.Encoding.DER))

# Command line interface for eith generating a root CA certificate or an intermediate CA certificate
def cli() -> None:
    import argparse

    parser = argparse.ArgumentParser(description='Generate a root CA certificate or an intermediate CA certificate.')
    parser.add_argument('-n', '--name', dest='name', type=str, required=True,
                        help='Name of the certificate to be generated.')
    parser.add_argument('-r', '--root', dest='root', action='store_true',
                        help='Generate a root CA certificate.')
    parser.add_argument('-i', '--intermediate', dest='intermediate', action='store_true',
                        help='Generate an intermediate CA certificate.')
    parser.add_argument('-c', '--crl', dest='crl', action='store_true',
                        help='Generate an empty crl.')
    args = parser.parse_args()

    if args.root:
        generate_root_ca_cert()
    elif args.intermediate:
        generate_intermediate_cert(args.name)
    elif args.crl:
        generate_crl(args.name)
    else:
        parser.print_help()

# Main function
if __name__ == '__main__':
    cli()
