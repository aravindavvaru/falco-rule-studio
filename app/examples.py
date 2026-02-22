EXAMPLE_RULES = [
    {
        "title": "Detect Shell in Container",
        "description": "Alert when a shell process is spawned inside a container",
        "yaml": """- rule: Shell spawned in a container
  desc: >
    A shell was spawned by a non-shell application inside a container.
    This may indicate an attacker is using the container to run arbitrary commands.
  condition: >
    spawned_process and container and
    shell_procs and
    not proc.pname in (shell_binaries)
  output: >
    Shell spawned in a container
    (user=%user.name user_loginuid=%user.loginuid
     %container.info shell=%proc.name parent=%proc.pname
     cmdline=%proc.cmdline pid=%proc.pid image=%container.image.repository)
  priority: WARNING
  tags: [container, shell, mitre_execution, T1059]"""
    },
    {
        "title": "Unexpected Outbound Network Connection",
        "description": "Alert on unexpected outbound network connections from containers",
        "yaml": """- rule: Unexpected outbound connection destination
  desc: >
    Detect outbound network connections to unexpected IP addresses,
    which may indicate data exfiltration or C2 communication.
  condition: >
    outbound and
    not trusted_containers and
    not fd.sip in (allowed_outbound_destination_ipaddrs)
  output: >
    Unexpected outbound connection destination
    (user=%user.name command=%proc.cmdline connection=%fd.name
     container_id=%container.id image=%container.image.repository)
  priority: NOTICE
  tags: [network, mitre_exfiltration, T1041]"""
    },
    {
        "title": "Write Below /etc",
        "description": "Alert when a process writes to /etc directory in a container",
        "yaml": """- rule: Write below etc
  desc: >
    An attempt to write to /etc directory was detected inside a container.
    Attackers may modify system configuration to establish persistence.
  condition: >
    write_etc_common
  output: >
    File below /etc opened for writing
    (user=%user.name user_loginuid=%user.loginuid
     command=%proc.cmdline parent=%proc.pname file=%fd.name
     program=%proc.name gparent=%proc.aname[2]
     container_id=%container.id image=%container.image.repository)
  priority: ERROR
  tags: [filesystem, mitre_persistence, T1543]"""
    }
]

EXAMPLE_PROMPTS = [
    "Alert when a process tries to read /etc/shadow or /etc/passwd inside a container",
    "Detect when kubectl is executed inside a pod",
    "Alert on any cryptocurrency mining process",
    "Detect when a container mounts a sensitive host directory like /proc or /sys",
    "Alert when more than 10 failed sudo attempts happen within a minute",
    "Detect when a new user is created on the system",
    "Alert when a process opens a reverse shell connection",
    "Detect when package managers (apt, yum, pip) run inside a container at runtime",
]

FALCO_FIELD_REFERENCE = """
## Common Falco Fields

### Process Fields
- `proc.name` - Process name
- `proc.exe` - Process executable path
- `proc.cmdline` - Full command line
- `proc.pid` - Process ID
- `proc.ppid` - Parent process ID
- `proc.pname` - Parent process name
- `proc.aname[n]` - Ancestor process name at depth n

### File/FD Fields
- `fd.name` - File descriptor name (file path or network address)
- `fd.directory` - Directory of the file descriptor
- `fd.filename` - Filename part of the file descriptor
- `fd.typechar` - Type: 'f'=file, '4'=IPv4, '6'=IPv6, 'u'=unix

### Network Fields
- `fd.sip` - Server IP address
- `fd.cip` - Client IP address
- `fd.sport` - Server port
- `fd.cport` - Client port
- `fd.rip` - Remote IP address
- `fd.rport` - Remote port

### Container Fields
- `container.id` - Container ID (or 'host' if not in container)
- `container.name` - Container name
- `container.image.repository` - Container image repository
- `container.image.tag` - Container image tag

### Kubernetes Fields
- `k8s.pod.name` - Kubernetes pod name
- `k8s.ns.name` - Kubernetes namespace name
- `k8s.deployment.name` - Deployment name

### User Fields
- `user.name` - Username
- `user.uid` - User ID
- `user.loginuid` - Login user ID

### Event Fields
- `evt.type` - Event type (execve, open, connect, etc.)
- `evt.dir` - Direction: '>' = enter, '<' = exit

### Syscall Macros
- `spawned_process` - A new process was spawned
- `container` - Event is in a container
- `outbound` - Outbound network connection
- `inbound` - Inbound network connection
- `open_write` - File opened for writing

## Priority Levels (highest to lowest)
EMERGENCY, ALERT, CRITICAL, ERROR, WARNING, NOTICE, INFORMATIONAL, DEBUG
"""
