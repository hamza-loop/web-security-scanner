import socket
import ssl
import certifi
from datetime import datetime, timezone


def analyze_tls(hostname, port=443):
    try:
        context = ssl.create_default_context(cafile=certifi.where())

        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(
                sock,
                server_hostname=hostname
            ) as tls_socket:

                certificate = tls_socket.getpeercert()

                expiry = datetime.strptime(
                    certificate["notAfter"],
                    "%b %d %H:%M:%S %Y %Z"
                )

                now = datetime.now(timezone.utc).replace(tzinfo=None)

                certificate_valid = expiry > now
                hostname_valid = True

                return {
                    "status": "success",
                    "tls_version": tls_socket.version(),
                    "certificate_valid": certificate_valid,
                    "hostname_valid": hostname_valid,
                    "subject": certificate["subject"],
                    "issuer": certificate["issuer"],
                    "valid_from": certificate["notBefore"],
                    "valid_until": certificate["notAfter"],
                    "subject_alt_names": certificate["subjectAltName"]
                }

    except ssl.SSLCertVerificationError as error:
        return {
            "status": "failed",
            "error_type": "certificate_verification",
            "error": str(error)
        }

    except ssl.SSLError as error:
        return {
            "status": "failed",
            "error_type": "tls_error",
            "error": str(error)
        }

    except socket.timeout as error:
        return {
            "status": "failed",
            "error_type": "timeout",
            "error": str(error)
        }

    except OSError as error:
        return {
            "status": "failed",
            "error_type": "connection_error",
            "error": str(error)
        }
    