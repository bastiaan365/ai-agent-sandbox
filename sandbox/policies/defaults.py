"""Default policy templates."""

# Restrictive policy - minimal privileges
RESTRICTIVE_POLICY = {
    "metadata": {
        "name": "restrictive",
        "version": "1.0",
        "description": "Highly restrictive sandbox policy for untrusted agents",
    },
    "filesystem": {
        "max_file_size": 1048576,  # 1MB
        "allowed_paths": ["/tmp/**"],
        "denied_paths": ["/etc/**", "/root/**", "/home/**"],
    },
    "network": {
        "allowed_hosts": [],
        "denied_hosts": [],
        "allowed_ports": [],
        "denied_ports": [],
    },
    "processes": {
        "allowed_commands": [],
        "denied_commands": ["rm", "dd", "mkfs", "shutdown", "reboot"],
    },
    "secrets": {
        "protected_vars": ["*API*", "*KEY*", "*TOKEN*", "*SECRET*", "*PASSWORD*"],
    },
    "resources": {
        "max_memory_mb": 256,
        "max_timeout_seconds": 30,
        "max_file_ops": 100,
        "max_network_requests": 0,
    },
}

# Permissive policy - development/testing
PERMISSIVE_POLICY = {
    "metadata": {
        "name": "permissive",
        "version": "1.0",
        "description": "Relaxed sandbox policy for development and testing",
    },
    "filesystem": {
        "max_file_size": 104857600,  # 100MB
        "allowed_paths": ["/tmp/**", "/home/**"],
        "denied_paths": ["/etc/sudoers", "/root/**"],
    },
    "network": {
        "allowed_hosts": ["*.example.com", "localhost", "127.0.0.1"],
        "denied_hosts": ["*.internal.corp"],
        "allowed_ports": [80, 443, 8000, 8080, 5000],
        "denied_ports": [],
    },
    "processes": {
        "allowed_commands": ["python*", "curl", "wget", "git"],
        "denied_commands": ["rm -rf", "dd", "mkfs"],
    },
    "secrets": {
        "protected_vars": ["AWS_*", "GCP_*"],
    },
    "resources": {
        "max_memory_mb": 1024,
        "max_timeout_seconds": 300,
        "max_file_ops": 10000,
        "max_network_requests": 1000,
    },
}

# Web agent policy - for agents that browse web
WEB_AGENT_POLICY = {
    "metadata": {
        "name": "web_agent",
        "version": "1.0",
        "description": "Policy for web browsing and API agents",
    },
    "filesystem": {
        "max_file_size": 52428800,  # 50MB
        "allowed_paths": ["/tmp/**", "/home/**/.cache/**"],
        "denied_paths": ["/etc/**", "/root/**"],
    },
    "network": {
        "allowed_hosts": [
            "*.github.com",
            "*.openai.com",
            "api.openai.com",
            "*.googleapis.com",
            "*.aws.amazon.com",
            "*.stripe.com",
            "*.discord.com",
            "*.example.com",
            "localhost",
        ],
        "denied_hosts": ["*.internal.*", "192.168.*", "10.0.*"],
        "allowed_ports": [80, 443],
        "denied_ports": [],
    },
    "processes": {
        "allowed_commands": ["curl", "wget", "python*"],
        "denied_commands": ["rm", "dd", "mkfs", "sudo"],
    },
    "secrets": {
        "protected_vars": ["AWS_*", "GCP_*", "*_SECRET", "*_PASSWORD"],
    },
    "resources": {
        "max_memory_mb": 512,
        "max_timeout_seconds": 120,
        "max_file_ops": 1000,
        "max_network_requests": 500,
    },
}
