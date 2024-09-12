def create_rules_dataframe(sg_config):
    inbound_rules = sg_config.get("IpPermissions", [])
    outbound_rules = sg_config.get("IpPermissionsEgress", [])
    
    def format_port_range(from_port, to_port):
        if from_port == to_port:
            return str(from_port)
        elif from_port == -1 and to_port == -1:
            return "All"
        else:
            return f"{from_port}-{to_port}"

    def create_rule_entries(rules, direction):
        entries = []
        for rule in rules:
            protocol = rule.get("IpProtocol", "All")
            from_port = rule.get("FromPort", "Any")
            to_port = rule.get("ToPort", "Any")
            port_range = format_port_range(from_port, to_port)
            for ip_range in rule.get("IpRanges", []):
                cidr = ip_range.get("CidrIp", "Any")
                entries.append({
                    "Direction": direction,
                    "Protocol": protocol,
                    "Port Range": port_range,
                    "Source/Destination": cidr
                })
        return entries
    
    all_entries = create_rule_entries(inbound_rules, "Inbound") + create_rule_entries(outbound_rules, "Outbound")
    return pd.DataFrame(all_entries)