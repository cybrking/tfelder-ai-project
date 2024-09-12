from collections import defaultdict

def is_port_sensitive(port):
    sensitive_ports = [22, 3389, 1433, 3306, 5432, 27017, 6379, 9200, 9300]
    return port in sensitive_ports

def is_large_port_range(from_port, to_port):
    return to_port - from_port > 100

def format_port_range(from_port, to_port):
    if from_port == to_port:
        return str(from_port)
    elif from_port == -1 and to_port == -1:
        return "All"
    else:
        return f"{from_port}-{to_port}"

def analyze_security_group(sg_config):
    issues = defaultdict(list)
    suggestions = defaultdict(list)
    
    inbound_rules = sg_config.get("IpPermissions", [])
    outbound_rules = sg_config.get("IpPermissionsEgress", [])

    for rule in inbound_rules + outbound_rules:
        protocol = rule.get("IpProtocol")
        from_port = rule.get("FromPort")
        to_port = rule.get("ToPort")
        port_range = format_port_range(from_port, to_port)
        
        for ip_range in rule.get("IpRanges", []):
            cidr = ip_range.get("CidrIp")
            if cidr == "0.0.0.0/0":
                if protocol == "-1":
                    issues["High"].append(f"Overly permissive rule: All traffic allowed from {cidr}")
                    suggestions["High"].append("Restrict traffic to only necessary protocols and ports")
                elif is_port_sensitive(from_port) or is_port_sensitive(to_port):
                    issues["High"].append(f"Overly permissive rule: {protocol} port {port_range} open to the world")
                    suggestions["High"].append(f"Restrict {protocol} port {port_range} to specific IP ranges or security groups")
                else:
                    issues["Medium"].append(f"Potentially overly permissive rule: {protocol} port {port_range} open to the world")
                    suggestions["Medium"].append(f"Consider restricting {protocol} port {port_range} to specific IP ranges or security groups")

        if from_port is not None and to_port is not None and is_large_port_range(from_port, to_port):
            issues["Medium"].append(f"Large port range: {port_range}")
            suggestions["Medium"].append(f"Consider narrowing the port range {port_range} to only necessary ports")

    if sg_config.get("GroupName") == "default":
        issues["Medium"].append("Default security group is being used")
        suggestions["Medium"].append("Consider creating custom security groups instead of using the default group")

    return issues, suggestions