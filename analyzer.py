security_analysis = {

    21: {

        "service": "FTP",

        "purpose": "File Transfer Protocol used for file sharing.",

        "risk_level": "HIGH",

        "risk": (
            "FTP transmits data "
            "without encryption."
        ),

        "recommendation": (
            "Use SFTP or FTPS "
            "instead of FTP."
        )

    },

    22: {

        "service": "SSH",

        "purpose": (
            "Secure remote login service."
        ),

        "risk_level": "MEDIUM",

        "risk": (
            "Weak passwords may allow "
            "brute-force attacks."
        ),

        "recommendation": (
            "Use SSH keys and "
            "disable root login."
        )

    },

    23: {

        "service": "Telnet",

        "purpose": (
            "Remote login protocol."
        ),

        "risk_level": "HIGH",

        "risk": (
            "Telnet sends credentials "
            "in plain text."
        ),

        "recommendation": (
            "Disable Telnet and use SSH."
        )

    },

    25: {

        "service": "SMTP",

        "purpose": (
            "Mail transfer service."
        ),

        "risk_level": "MEDIUM",

        "risk": (
            "Open mail relays may be "
            "abused for spam."
        ),

        "recommendation": (
            "Restrict mail relay access."
        )

    },

    53: {

        "service": "DNS",

        "purpose": (
            "Domain Name Resolution service."
        ),

        "risk_level": "MEDIUM",

        "risk": (
            "DNS amplification attacks "
            "may occur."
        ),

        "recommendation": (
            "Restrict recursive queries."
        )

    },

    67: {

        "service": "DHCP",

        "purpose": "Dynamic IP address assignment for network hosts.",

        "risk_level": "MEDIUM",

        "risk": (
            "Rogue DHCP servers can hijack "
            "network configuration for clients."
        ),

        "recommendation": (
            "Restrict DHCP to trusted servers "
            "and enable DHCP snooping on switches."
        )

    },

    68: {

        "service": "DHCP",

        "purpose": "DHCP client-side communication.",

        "risk_level": "MEDIUM",

        "risk": (
            "Susceptible to the same rogue-server "
            "risks as the DHCP server port."
        ),

        "recommendation": (
            "Use DHCP snooping and restrict "
            "untrusted ports on switches."
        )

    },

    69: {

        "service": "TFTP",

        "purpose": "Trivial File Transfer Protocol, used for simple file transfers (often firmware/config).",

        "risk_level": "HIGH",

        "risk": (
            "TFTP has no authentication or "
            "encryption whatsoever."
        ),

        "recommendation": (
            "Disable TFTP if unused, or restrict "
            "access to trusted management networks only."
        )

    },

    80: {

        "service": "HTTP",

        "purpose": (
            "Web server communication."
        ),

        "risk_level": "MEDIUM",

        "risk": (
            "HTTP traffic is not encrypted."
        ),

        "recommendation": (
            "Use HTTPS instead of HTTP."
        )

    },

    135: {

        "service": "RPC",

        "purpose": (
            "Remote Procedure Call service "
            "used by Windows."
        ),

        "risk_level": "HIGH",

        "risk": (
            "RPC services may be exploited "
            "for remote code execution."
        ),

        "recommendation": (
            "Restrict RPC access using "
            "firewalls and keep systems updated."
        )

    },

    137: {

        "service": "NetBIOS",

        "purpose": "NetBIOS Name Service, used for name resolution on legacy Windows networks.",

        "risk_level": "HIGH",

        "risk": (
            "Exposes hostnames and can be abused "
            "for enumeration or spoofing attacks."
        ),

        "recommendation": (
            "Disable NetBIOS over TCP/IP where "
            "not required."
        )

    },

    138: {

        "service": "NetBIOS",

        "purpose": "NetBIOS Datagram Service, used for connectionless communication.",

        "risk_level": "HIGH",

        "risk": (
            "Can leak network information and "
            "enable spoofing."
        ),

        "recommendation": (
            "Disable NetBIOS over TCP/IP where "
            "not required."
        )

    },

    139: {

        "service": "SMB",

        "purpose": (
            "Windows file sharing service."
        ),

        "risk_level": "HIGH",

        "risk": (
            "SMB vulnerabilities may expose "
            "shared resources."
        ),

        "recommendation": (
            "Disable SMBv1 and restrict access."
        )

    },

    161: {

        "service": "SNMP",

        "purpose": "Simple Network Management Protocol, used to monitor and manage network devices.",

        "risk_level": "HIGH",

        "risk": (
            "Default community strings (e.g. "
            "'public') expose device configuration."
        ),

        "recommendation": (
            "Use SNMPv3 with authentication and "
            "change default community strings."
        )

    },

    179: {

        "service": "BGP",

        "purpose": "Border Gateway Protocol, used for routing between networks.",

        "risk_level": "HIGH",

        "risk": (
            "Unauthorized BGP sessions can "
            "redirect or black-hole traffic."
        ),

        "recommendation": (
            "Restrict BGP peers and use "
            "authentication (e.g. MD5/TCP-AO)."
        )

    },

    389: {

        "service": "LDAP",

        "purpose": "Lightweight Directory Access Protocol, used for directory/authentication services.",

        "risk_level": "HIGH",

        "risk": (
            "Unencrypted LDAP exposes credentials "
            "and directory data in transit."
        ),

        "recommendation": (
            "Use LDAPS (port 636) and restrict "
            "access to trusted hosts."
        )

    },

    443: {

        "service": "HTTPS",

        "purpose": (
            "Secure web communication."
        ),

        "risk_level": "LOW",

        "risk": (
            "Weak TLS configurations may "
            "be vulnerable."
        ),

        "recommendation": (
            "Use modern TLS configurations."
        )

    },

    445: {

        "service": "SMB",

        "purpose": (
            "File and printer sharing "
            "service used in Windows."
        ),

        "risk_level": "HIGH",

        "risk": (
            "SMB vulnerabilities may allow "
            "unauthorized access or ransomware attacks."
        ),

        "recommendation": (
            "Disable SMBv1, restrict access, "
            "and apply security patches."
        )

    },

    465: {

        "service": "SMTPS",

        "purpose": "Encrypted mail submission over SSL/TLS.",

        "risk_level": "LOW",

        "risk": (
            "Weak TLS configurations may "
            "still be exploitable."
        ),

        "recommendation": (
            "Enforce modern TLS versions and "
            "strong cipher suites."
        )

    },

    514: {

        "service": "Syslog",

        "purpose": "Remote system logging.",

        "risk_level": "MEDIUM",

        "risk": (
            "Syslog over UDP is unauthenticated "
            "and can be spoofed or intercepted."
        ),

        "recommendation": (
            "Use encrypted syslog (e.g. over TLS) "
            "and restrict source IPs."
        )

    },

    587: {

        "service": "SMTP Submission",

        "purpose": "Mail submission from clients, typically with authentication.",

        "risk_level": "MEDIUM",

        "risk": (
            "Weak authentication may allow "
            "unauthorized mail relaying."
        ),

        "recommendation": (
            "Enforce strong authentication and "
            "require STARTTLS."
        )

    },

    993: {

        "service": "IMAPS",

        "purpose": "Encrypted IMAP for retrieving email.",

        "risk_level": "LOW",

        "risk": (
            "Weak TLS configurations may "
            "still be exploitable."
        ),

        "recommendation": (
            "Enforce modern TLS versions and "
            "strong cipher suites."
        )

    },

    995: {

        "service": "POP3S",

        "purpose": "Encrypted POP3 for retrieving email.",

        "risk_level": "LOW",

        "risk": (
            "Weak TLS configurations may "
            "still be exploitable."
        ),

        "recommendation": (
            "Enforce modern TLS versions and "
            "strong cipher suites."
        )

    },

    1433: {

        "service": "MSSQL",

        "purpose": "Microsoft SQL Server database service.",

        "risk_level": "HIGH",

        "risk": (
            "Unauthorized access can expose or "
            "modify sensitive database contents."
        ),

        "recommendation": (
            "Restrict remote access, use strong "
            "authentication, and apply patches."
        )

    },

    1521: {

        "service": "Oracle DB",

        "purpose": "Oracle database listener service.",

        "risk_level": "HIGH",

        "risk": (
            "Unauthorized access can expose or "
            "modify sensitive database contents."
        ),

        "recommendation": (
            "Restrict remote access, use strong "
            "authentication, and apply patches."
        )

    },

    2049: {

        "service": "NFS",

        "purpose": "Network File System, used for sharing files across Unix/Linux systems.",

        "risk_level": "HIGH",

        "risk": (
            "Misconfigured exports can allow "
            "unauthorized file access."
        ),

        "recommendation": (
            "Restrict exports to trusted hosts "
            "and disable if unused."
        )

    },

    3306: {

        "service": "MySQL",

        "purpose": (
            "Database server service."
        ),

        "risk_level": "HIGH",

        "risk": (
            "Unauthorized database access "
            "may occur."
        ),

        "recommendation": (
            "Restrict remote access and "
            "use strong passwords."
        )

    },

    3389: {

        "service": "RDP",

        "purpose": (
            "Remote Desktop service."
        ),

        "risk_level": "HIGH",

        "risk": (
            "RDP may be targeted by "
            "brute-force attacks."
        ),

        "recommendation": (
            "Restrict RDP access and "
            "enable MFA."
        )

    },

    5432: {

        "service": "PostgreSQL",

        "purpose": "PostgreSQL database service.",

        "risk_level": "HIGH",

        "risk": (
            "Unauthorized access can expose or "
            "modify sensitive database contents."
        ),

        "recommendation": (
            "Restrict remote access, use strong "
            "authentication, and apply patches."
        )

    },

    5900: {

        "service": "VNC",

        "purpose": "Virtual Network Computing, used for remote desktop access.",

        "risk_level": "HIGH",

        "risk": (
            "Often runs with weak or no "
            "authentication, enabling remote takeover."
        ),

        "recommendation": (
            "Use strong passwords, tunnel over "
            "SSH/VPN, and restrict access."
        )

    },

    6379: {

        "service": "Redis",

        "purpose": "In-memory data store, often used for caching.",

        "risk_level": "HIGH",

        "risk": (
            "Frequently exposed without "
            "authentication, allowing full data access."
        ),

        "recommendation": (
            "Enable authentication, bind to "
            "localhost/trusted networks only."
        )

    },

    8080: {

        "service": "HTTP Proxy",

        "purpose": "Alternate HTTP port, often used for proxies or web apps.",

        "risk_level": "MEDIUM",

        "risk": (
            "May expose unencrypted or "
            "misconfigured web services."
        ),

        "recommendation": (
            "Use HTTPS and restrict access to "
            "intended clients."
        )

    },

    8443: {

        "service": "HTTPS Alt",

        "purpose": "Alternate HTTPS port, often used for admin panels or web apps.",

        "risk_level": "LOW",

        "risk": (
            "Weak TLS configurations may "
            "still be exploitable."
        ),

        "recommendation": (
            "Enforce modern TLS versions and "
            "restrict access to intended clients."
        )

    }

}