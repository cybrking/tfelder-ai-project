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

def analyze_security_group(sg_config):
    issues = defaultdict(list)
    suggestions = defaultdict(list)
    
    inbound_rules = sg_config.get("IpPermissions", [])
    outbound_rules = sg_config.get("IpPermissionsEgress", [])

    for rule in inbound_rules:
        protocol = rule.get("IpProtocol")
        from_port = rule.get("FromPort")
        to_port = rule.get("ToPort")
        
        for ip_range in rule.get("IpRanges", []):
            cidr = ip_range.get("CidrIp")
            if cidr == "0.0.0.0/0":
                issues["High"].append(f"Overly permissive inbound rule: {protocol} {from_port}-{to_port} open to the world")
                suggestions["High"].append(f"Restrict {protocol} {from_port}-{to_port} to specific IP ranges or security groups")

    for rule in outbound_rules:
        if rule.get("IpProtocol") == "-1" and rule.get("FromPort") == -1 and rule.get("ToPort") == -1:
            for ip_range in rule.get("IpRanges", []):
                if ip_range.get("CidrIp") == "0.0.0.0/0":
                    issues["Low"].append("All outbound traffic is allowed")
                    suggestions["Low"].append("Consider restricting outbound traffic to necessary destinations and ports")

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
    st.title("Security Group Configuration Analyzer")

    uploaded_file = st.file_uploader("Choose a security group configuration file", type=["json"])
    
    if uploaded_file is not None:
        file_contents = uploaded_file.getvalue().decode("utf-8")
        
        st.subheader("File Contents")
        st.code(file_contents)

        sg_configs = parse_security_groups(file_contents)
        
        if sg_configs:
            for i, sg_config in enumerate(sg_configs):
                st.subheader(f"Security Group {i+1}: {sg_config.get('GroupName', 'Unnamed')}")
                
                issues, suggestions = analyze_security_group(sg_config)
                
                st.subheader("Analysis Results")
                for severity in ["High", "Medium", "Low"]:
                    if issues.get(severity):
                        for issue, suggestion in zip(issues[severity], suggestions[severity]):
                            st.warning(issue)
                            st.info(f"Suggestion: {suggestion}")

                st.subheader("Security Group Rules Visualization")
                fig = visualize_security_group(sg_config)
                st.plotly_chart(fig, use_container_width=True)

if __name__ == "__main__":
    main()