import streamlit as st
import json
from collections import defaultdict
import plotly.graph_objects as go
import base64
import io
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import networkx as nx

def parse_security_groups(file_contents):
    try:
        data = json.loads(file_contents)
        if isinstance(data, dict):
            return [data]
        elif isinstance(data, list):
            return data
        else:
            st.error(f"Invalid JSON structure. Expected a dictionary or a list of dictionaries. Got: {type(data)}")
            return None
    except json.JSONDecodeError as e:
        st.error(f"Invalid JSON file: {str(e)}")
        return None
    except Exception as e:
        st.error(f"An unexpected error occurred while parsing the security groups: {str(e)}")
        return None

def is_port_sensitive(port):
    sensitive_ports = [22, 3389, 1433, 3306, 5432, 27017, 6379, 9200, 9300]
    return port in sensitive_ports

def is_large_port_range(from_port, to_port):
    return to_port - from_port > 100

def analyze_security_group(sg_config):
    issues = defaultdict(list)
    suggestions = defaultdict(list)
    
    inbound_rules = sg_config.get("IpPermissions", [])
    outbound_rules = sg_config.get("IpPermissionsEgress", [])

    # Check for overly permissive rules
    for rule in inbound_rules + outbound_rules:
        protocol = rule.get("IpProtocol")
        from_port = rule.get("FromPort")
        to_port = rule.get("ToPort")
        
        for ip_range in rule.get("IpRanges", []):
            cidr = ip_range.get("CidrIp")
            if cidr == "0.0.0.0/0":
                if protocol == "-1":
                    issues["High"].append(f"Overly permissive rule: All traffic allowed from {cidr}")
                    suggestions["High"].append("Restrict traffic to only necessary protocols and ports")
                elif is_port_sensitive(from_port) or is_port_sensitive(to_port):
                    issues["High"].append(f"Overly permissive rule: {protocol} {from_port}-{to_port} open to the world")
                    suggestions["High"].append(f"Restrict {protocol} {from_port}-{to_port} to specific IP ranges or security groups")
                else:
                    issues["Medium"].append(f"Potentially overly permissive rule: {protocol} {from_port}-{to_port} open to the world")
                    suggestions["Medium"].append(f"Consider restricting {protocol} {from_port}-{to_port} to specific IP ranges or security groups")

    # Check for large port ranges
    for rule in inbound_rules + outbound_rules:
        from_port = rule.get("FromPort")
        to_port = rule.get("ToPort")
        if from_port is not None and to_port is not None and is_large_port_range(from_port, to_port):
            issues["Medium"].append(f"Large port range: {from_port}-{to_port}")
            suggestions["Medium"].append(f"Consider narrowing the port range {from_port}-{to_port} to only necessary ports")

    # Check for rule duplication
    rule_set = set()
    for rule in inbound_rules + outbound_rules:
        rule_tuple = (
            rule.get("IpProtocol"),
            rule.get("FromPort"),
            rule.get("ToPort"),
            frozenset((ip_range.get("CidrIp") for ip_range in rule.get("IpRanges", [])))
        )
        if rule_tuple in rule_set:
            issues["Low"].append(f"Duplicate rule: {rule}")
            suggestions["Low"].append("Remove duplicate rule to simplify security group configuration")
        else:
            rule_set.add(rule_tuple)

    # Check if it's the default security group
    if sg_config.get("GroupName") == "default":
        issues["Medium"].append("Default security group is being used")
        suggestions["Medium"].append("Consider creating custom security groups instead of using the default group")

    return issues, suggestions

def visualize_security_group(sg_config):
    def create_rule_text(rule):
        protocol = rule.get("IpProtocol")
        from_port = rule.get("FromPort")
        to_port = rule.get("ToPort")
        cidrs = [ip_range.get("CidrIp") for ip_range in rule.get("IpRanges", [])]
        return f"{protocol} {from_port}-{to_port} from {', '.join(cidrs)}"

    inbound_rules = [create_rule_text(rule) for rule in sg_config.get("IpPermissions", [])]
    outbound_rules = [create_rule_text(rule) for rule in sg_config.get("IpPermissionsEgress", [])]

    fig = go.Figure(data=[go.Table(
        header=dict(values=["Inbound Rules", "Outbound Rules"]),
        cells=dict(values=[inbound_rules, outbound_rules])
    )])

    fig.update_layout(title="Security Group Rules Visualization")
    return fig

def main():
    st.title("Enhanced Security Group Configuration Analyzer")

    uploaded_file = st.file_uploader("Choose a security group configuration file", type=["json"])
    
    if uploaded_file is not None:
        try:
            file_contents = uploaded_file.getvalue().decode("utf-8")
            
            st.subheader("File Contents")
            st.code(file_contents)

            sg_configs = parse_security_groups(file_contents)
            
            if sg_configs:
                for i, sg_config in enumerate(sg_configs):
                    st.subheader(f"Security Group {i+1}: {sg_config.get('GroupName', 'Unnamed')}")
                    
                    try:
                        issues, suggestions = analyze_security_group(sg_config)
                        
                        st.subheader("Analysis Results")
                        for severity in ["High", "Medium", "Low"]:
                            if issues.get(severity):
                                st.write(f"{severity} Severity Issues:")
                                for issue, suggestion in zip(issues[severity], suggestions[severity]):
                                    st.warning(issue)
                                    st.info(f"Suggestion: {suggestion}")
                                st.write("---")

                        if not any(issues.values()):
                            st.success("No issues found in this security group.")

                        st.subheader("Security Group Rules Visualization")
                        fig = visualize_security_group(sg_config)
                        st.plotly_chart(fig, use_container_width=True)
                    except Exception as e:
                        st.error(f"An error occurred while analyzing security group {i+1}: {str(e)}")
        except Exception as e:
            st.error(f"An error occurred while processing the file: {str(e)}")

    st.sidebar.title("About")
    st.sidebar.info(
        "This app analyzes AWS Security Group configurations for potential security issues. "
        "It checks for overly permissive rules, large port ranges, rule duplication, "
        "and use of the default security group."
    )

if __name__ == "__main__":
    main()