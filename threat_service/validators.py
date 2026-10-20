"""
Threat value validation (Threat Intelligence Service).
Implemented by: Hayam Itani

Brief: validate the IP address format for IP threats, the domain format for domain
threats and the hash format for file hashes.

Each validator also NORMALISES the value (for example lower-case), so the duplicate check
(same type + value -> 409) cannot be bypassed by changing the letter case.
"""
import ipaddress
import re
from abc import ABC, abstractmethod

from shared.errors import ValidationError
from shared.security import clean_text

# one label = letters/digits/hyphens, not starting or ending with "-"; last label (TLD) letters only
DOMAIN_RE = re.compile(r"^(?:(?!-)[a-z0-9-]{1,63}(?<!-)\.)+[a-z]{2,63}$")
HEX_RE = re.compile(r"^[0-9a-f]+$")



class IndicatorValidator(ABC):
    """Base class: checks and normalises one kind of threat value."""

    @abstractmethod
    def validate(self, value):
        """Check the format and return the value to store.

        :param value: raw threat_value from the request
        :type value: str
        :return: normalised value
        :rtype: str
        :raises ValidationError: wrong format for this type
        """


class IPAddressValidator(IndicatorValidator):
    """IPv4 or IPv6, e.g. 203.0.113.45"""

    def validate(self, value):
        """Check an IP address with the standard ``ipaddress`` module.

        :param value: raw threat_value from the request
        :type value: str
        :return: the address in its standard text form (spaces removed)
        :rtype: str
        :raises ValidationError: not a valid IPv4 or IPv6 address
        """
        try:
            return str(ipaddress.ip_address(value.strip()))
        except ValueError:
            raise ValidationError(f"Invalid IP address: '{value}'")



class DomainValidator(IndicatorValidator):
    """e.g. login-update.example"""

    def validate(self, value):
        """Check a domain name against DOMAIN_RE.

        :param value: raw threat_value from the request
        :type value: str
        :return: the domain in lower case, without a trailing dot
        :rtype: str
        :raises ValidationError: not a valid domain name
        """
        domain = value.strip().lower().rstrip(".")
        if len(domain) > 253 or not DOMAIN_RE.match(domain):
            raise ValidationError(f"Invalid domain: '{value}'")
        return domain



class FileHashValidator(IndicatorValidator):
    """MD5 (32), SHA-1 (40) or SHA-256 (64) hex characters."""

    def validate(self, value):
        """Check a file hash: hexadecimal, 32, 40 or 64 characters long.

        :param value: raw threat_value from the request
        :type value: str
        :return: the hash in lower case
        :rtype: str
        :raises ValidationError: wrong length or non-hexadecimal characters
        """
        digest = value.strip().lower()
        if len(digest) not in (32, 40, 64) or not HEX_RE.match(digest):
            raise ValidationError("Invalid file hash: expected MD5 (32), SHA-1 (40) or SHA-256 (64) "
                                  "hexadecimal characters")
        return digest



class FreeTextValidator(IndicatorValidator):
    """Malware Signature and Other: free text, cleaned like every other text field."""

    def validate(self, value):
        """Clean free text with the shared ``clean_text`` helper.

        :param value: raw threat_value from the request
        :type value: str
        :return: the trimmed text
        :rtype: str
        :raises ValidationError: too short, too long, or contains forbidden characters
        """
        return clean_text(value, "threat_value", 2, 255)



# Which validator checks which threat type
VALIDATORS = {
    "IP Address": IPAddressValidator(),
    "Domain": DomainValidator(),
    "File Hash": FileHashValidator(),
    "Malware Signature": FreeTextValidator(),
    "Other": FreeTextValidator(),
}



def validate_threat_value(threat_type, value):
    """Pick the validator for the type and run it.

    :param threat_type: one of Threat.TYPES (already validated)
    :type threat_type: str
    :param value: raw threat_value
    :type value: str
    :return: normalised value
    :rtype: str
    :raises ValidationError: not a string, or wrong format for this type
    """
    if not isinstance(value, str):
        raise ValidationError("'threat_value' must be a string")
    return VALIDATORS[threat_type].validate(value)

