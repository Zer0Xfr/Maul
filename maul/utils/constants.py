WELL_KNOWN_SIDS: dict[str, str] = {
    "S-1-0-0": "NULL SID",
    "S-1-1-0": "Everyone",
    "S-1-2-0": "Local",
    "S-1-3-0": "Creator Owner",
    "S-1-3-1": "Creator Group",
    "S-1-5-1": "Dialup",
    "S-1-5-2": "Network",
    "S-1-5-4": "Interactive",
    "S-1-5-6": "Service",
    "S-1-5-7": "Anonymous",
    "S-1-5-9": "Enterprise Domain Controllers",
    "S-1-5-10": "Principal Self",
    "S-1-5-11": "Authenticated Users",
    "S-1-5-12": "Restricted Code",
    "S-1-5-13": "Terminal Server User",
    "S-1-5-14": "Remote Interactive Logon",
    "S-1-5-15": "This Organization",
    "S-1-5-18": "SYSTEM",
    "S-1-5-19": "NT Authority\\Local Service",
    "S-1-5-20": "NT Authority\\Network Service",
    "S-1-5-32-544": "BUILTIN\\Administrators",
    "S-1-5-32-545": "BUILTIN\\Users",
    "S-1-5-32-546": "BUILTIN\\Guests",
    "S-1-5-32-547": "BUILTIN\\Power Users",
    "S-1-5-32-548": "BUILTIN\\Account Operators",
    "S-1-5-32-549": "BUILTIN\\Server Operators",
    "S-1-5-32-550": "BUILTIN\\Print Operators",
    "S-1-5-32-551": "BUILTIN\\Backup Operators",
    "S-1-5-32-552": "BUILTIN\\Replicators",
    "S-1-5-32-554": "BUILTIN\\Pre-Windows 2000 Compatible Access",
    "S-1-5-32-555": "BUILTIN\\Remote Desktop Users",
    "S-1-5-32-556": "BUILTIN\\Network Configuration Operators",
    "S-1-5-32-557": "BUILTIN\\Incoming Forest Trust Builders",
    "S-1-5-32-558": "BUILTIN\\Performance Monitor Users",
    "S-1-5-32-559": "BUILTIN\\Performance Log Users",
    "S-1-5-32-560": "BUILTIN\\Windows Authorization Access Group",
    "S-1-5-32-568": "BUILTIN\\IIS_IUSRS",
    "S-1-5-32-569": "BUILTIN\\Cryptographic Operators",
    "S-1-5-32-573": "BUILTIN\\Event Log Readers",
    "S-1-5-32-574": "BUILTIN\\Certificate Service DCOM Access",
    "S-1-5-32-578": "BUILTIN\\Hyper-V Administrators",
    "S-1-5-32-579": "BUILTIN\\Access Control Assistance Operators",
    "S-1-5-32-580": "BUILTIN\\Remote Management Users",
}

# RID-suffix → name for domain-relative SIDs (append to domain SID prefix)
DOMAIN_RELATIVE_SIDS: dict[str, str] = {
    "-500": "Administrator",
    "-501": "Guest",
    "-502": "KRBTGT",
    "-512": "Domain Admins",
    "-513": "Domain Users",
    "-514": "Domain Guests",
    "-515": "Domain Computers",
    "-516": "Domain Controllers",
    "-517": "Cert Publishers",
    "-518": "Schema Admins",
    "-519": "Enterprise Admins",
    "-520": "Group Policy Creator Owners",
    "-521": "Read-Only Domain Controllers",
    "-522": "Cloneable Domain Controllers",
    "-525": "Protected Users",
    "-526": "Key Admins",
    "-527": "Enterprise Key Admins",
    "-553": "RAS and IAS Servers",
}

PRIVILEGED_GROUP_RIDS: list[str] = [
    "-512",  # Domain Admins
    "-518",  # Schema Admins
    "-519",  # Enterprise Admins
    "-520",  # Group Policy Creator Owners
    "-526",  # Key Admins
    "-527",  # Enterprise Key Admins
]

PRIVILEGED_BUILTIN_SIDS: list[str] = [
    "S-1-5-32-544",  # Administrators
    "S-1-5-32-548",  # Account Operators
    "S-1-5-32-549",  # Server Operators
    "S-1-5-32-550",  # Print Operators
    "S-1-5-32-551",  # Backup Operators
]

EXTENDED_RIGHTS: dict[str, str] = {
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes-All",
    "89e95b76-444d-4c62-991a-0facbeda640c": "DS-Replication-Get-Changes-In-Filtered-Set",
    "1131f6ab-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Synchronize",
    "1131f6ac-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Manage-Topology",
    "00299570-246d-11d0-a768-00aa006e0529": "User-Force-Change-Password",
    "ab721a53-1e2f-11d0-9819-00aa0040529b": "User-Change-Password",
    "0e10c968-78fb-11d2-90d4-00c04f79dc55": "Certificate-Enrollment",
    "a05b8cc2-17bc-4802-a710-e7c15ab866a2": "Certificate-AutoEnrollment",
    "ab721a54-1e2f-11d0-9819-00aa0040529b": "Send-As",
    "ab721a56-1e2f-11d0-9819-00aa0040529b": "Receive-As",
    "68b1d179-0d15-4d4f-ab71-46152e79a7bc": "Allowed-To-Authenticate",
    "9b026da6-0d3c-465c-8bee-5199d7165cba": "DS-Validated-Write-Computer",
    "f3a64788-5306-11d1-a9c5-0000f80367c1": "Validated-SPN",
    "72e39547-7b18-11d1-adef-00c04fd8d5cd": "DNS-Host-Name-Attributes",
    "4c164200-20c0-11d0-a768-00aa006e0529": "User-Account-Restrictions",
    "ba33815a-4f93-4c76-87f3-57574bff8109": "Migrate-SID-History",
    "45ec5156-db7e-47bb-b53f-dbeb2d03c40f": "Reanimate-Tombstones",
    "3e0f7e18-2c7a-4c10-ba82-4d926db99a3e": "DS-Clone-Domain-Controller",
}

UAC_FLAGS: dict[int, str] = {
    0x0001: "SCRIPT",
    0x0002: "ACCOUNTDISABLE",
    0x0008: "HOMEDIR_REQUIRED",
    0x0010: "LOCKOUT",
    0x0020: "PASSWD_NOTREQD",
    0x0040: "PASSWD_CANT_CHANGE",
    0x0080: "ENCRYPTED_TEXT_PWD_ALLOWED",
    0x0100: "TEMP_DUPLICATE_ACCOUNT",
    0x0200: "NORMAL_ACCOUNT",
    0x0800: "INTERDOMAIN_TRUST_ACCOUNT",
    0x1000: "WORKSTATION_TRUST_ACCOUNT",
    0x2000: "SERVER_TRUST_ACCOUNT",
    0x10000: "DONT_EXPIRE_PASSWORD",
    0x20000: "MNS_LOGON_ACCOUNT",
    0x40000: "SMARTCARD_REQUIRED",
    0x80000: "TRUSTED_FOR_DELEGATION",
    0x100000: "NOT_DELEGATED",
    0x200000: "USE_DES_KEY_ONLY",
    0x400000: "DONT_REQUIRE_PREAUTH",
    0x800000: "PASSWORD_EXPIRED",
    0x1000000: "TRUSTED_TO_AUTH_FOR_DELEGATION",
    0x4000000: "PARTIAL_SECRETS_ACCOUNT",
}

DOMAIN_FUNCTIONAL_LEVELS: dict[int, str] = {
    0: "Windows 2000",
    1: "Windows Server 2003 Interim",
    2: "Windows Server 2003",
    3: "Windows Server 2008",
    4: "Windows Server 2008 R2",
    5: "Windows Server 2012",
    6: "Windows Server 2012 R2",
    7: "Windows Server 2016",
    8: "Windows Server 2019",
    10: "Windows Server 2022",
}

FOREST_FUNCTIONAL_LEVELS = DOMAIN_FUNCTIONAL_LEVELS.copy()

TRUST_ATTRIBUTES: dict[int, str] = {
    0x0001: "NON_TRANSITIVE",
    0x0002: "UPLEVEL_ONLY",
    0x0004: "QUARANTINED_DOMAIN",
    0x0008: "FOREST_TRANSITIVE",
    0x0010: "CROSS_ORGANIZATION",
    0x0020: "WITHIN_FOREST",
    0x0040: "TREAT_AS_EXTERNAL",
    0x0080: "USES_RC4_ENCRYPTION",
    0x0200: "NO_TGT_DELEGATION",
    0x0400: "PIM_TRUST",
}

TRUST_DIRECTION: dict[int, str] = {
    0: "Disabled",
    1: "Inbound",
    2: "Outbound",
    3: "Bidirectional",
}

TRUST_TYPE: dict[int, str] = {
    1: "Windows NT (non-AD)",
    2: "Active Directory",
    3: "MIT (non-Windows Kerberos)",
    4: "DCE",
}

# Certificate extended key usage OIDs
EKU_OIDS: dict[str, str] = {
    "1.3.6.1.5.5.7.3.1": "Server Authentication",
    "1.3.6.1.5.5.7.3.2": "Client Authentication",
    "1.3.6.1.5.5.7.3.3": "Code Signing",
    "1.3.6.1.5.5.7.3.4": "Email Protection",
    "1.3.6.1.4.1.311.20.2.2": "Smart Card Logon",
    "1.3.6.1.5.2.3.4": "PKINIT Client Authentication",
    "1.3.6.1.5.5.7.3.8": "Time Stamping",
    "2.5.29.37.0": "Any Purpose",
    "1.3.6.1.4.1.311.10.3.4": "Encrypting File System",
    "1.3.6.1.4.1.311.21.6": "Key Recovery Agent",
    "1.3.6.1.4.1.311.10.3.11": "Key Recovery",
}

# pKICertificateTemplate flags
CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001
CT_FLAG_ANY_PURPOSE = 0x00000008
CT_FLAG_ENABLED = 0x20000000

# msPKI-Certificate-Name-Flag
SUBJECT_REQUIRE_DIRECTORY_PATH = 0x80000000
SUBJECT_REQUIRE_COMMON_NAME = 0x40000000
SUBJECT_REQUIRE_EMAIL = 0x20000000
SUBJECT_REQUIRE_DNS_AS_CN = 0x10000000
SUBJECT_ALT_REQUIRE_DNS = 0x08000000
SUBJECT_ALT_REQUIRE_EMAIL = 0x04000000
SUBJECT_ALT_REQUIRE_UPN = 0x02000000
SUBJECT_ALT_REQUIRE_DIRECTORY_GUID = 0x01000000

# Dangerous AD rights bitmasks for ACL checks
AD_RIGHT_DELETE = 0x00010000
AD_RIGHT_READ_CONTROL = 0x00020000
AD_RIGHT_WRITE_DAC = 0x00040000
AD_RIGHT_WRITE_OWNER = 0x00080000
AD_RIGHT_CREATE_CHILD = 0x00000001
AD_RIGHT_DELETE_CHILD = 0x00000002
AD_RIGHT_SELF_WRITE = 0x00000008
AD_RIGHT_WRITE_PROPERTY = 0x00000020
AD_RIGHT_EXTENDED_RIGHT = 0x00000100
AD_RIGHT_GENERIC_ALL = 0x10000000
AD_RIGHT_GENERIC_WRITE = 0x40000000

DANGEROUS_RIGHTS: frozenset[int] = frozenset({
    AD_RIGHT_GENERIC_ALL,
    AD_RIGHT_GENERIC_WRITE,
    AD_RIGHT_WRITE_DAC,
    AD_RIGHT_WRITE_OWNER,
})
