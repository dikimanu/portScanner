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

    }

}

