import streamlit as st
import json
from collections import defaultdict
import pandas as pd

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

        if from_port is not None and to_port is not None and is_large_port_range(from_port, to_port):
            issues["Medium"].append(f"Large port range: {from_port}-{to_port}")
            suggestions["Medium"].append(f"Consider narrowing the port range {from_port}-{to_port} to only necessary ports")

    if sg_config.get("GroupName") == "default":
        issues["Medium"].append("Default security group is being used")
        suggestions["Medium"].append("Consider creating custom security groups instead of using the default group")

    return issues, suggestions

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

def main():
    st.set_page_config(layout="wide", page_title="Security Group Analyzer")

    st.title("🛡️ AWS Security Group Analyzer")

    # Add radio button for input method selection
    input_method = st.radio("Choose input method:", ("Upload JSON file", "Paste JSON text"))

    if input_method == "Upload JSON file":
        uploaded_file = st.file_uploader("Choose a security group configuration file", type=["json"])
        if uploaded_file is not None:
            file_contents = uploaded_file.getvalue().decode("utf-8")
    else:
        file_contents = st.text_area("Paste your security group configuration JSON here:", height=300)

    if file_contents:
        try:
            sg_configs = parse_security_groups(file_contents)
            
            if sg_configs:
                for i, sg_config in enumerate(sg_configs):
                    st.markdown(f"## Security Group: {sg_config.get('GroupName', 'Unnamed')}")
                    
                    # Create and display the rules table
                    st.markdown("### Security Group Rules")
                    rules_df = create_rules_dataframe(sg_config)
                    st.dataframe(
                        rules_df,
                        column_config={
                            "Direction": st.column_config.TextColumn("Direction", width="medium"),
                            "Protocol": st.column_config.TextColumn("Protocol", width="medium"),
                            "Port Range": st.column_config.TextColumn("Port Range", width="medium"),
                            "Source/Destination": st.column_config.TextColumn("Source/Destination", width="large")
                        },
                        hide_index=True,
                        use_container_width=True
                    )

                    # Analysis Results
                    st.markdown("### 🔍 Analysis Results")
                    issues, suggestions = analyze_security_group(sg_config)
                    
                    if not any(issues.values()):
                        st.success("✅ No issues found in this security group.")
                    else:
                        for severity in ["High", "Medium", "Low"]:
                            if issues.get(severity):
                                with st.expander(f"{severity.upper()} Severity Issues", expanded=(severity == "High")):
                                    for issue, suggestion in zip(issues[severity], suggestions[severity]):
                                        st.markdown(f"""
                                        <div style="background-color: {'#FFCCCB' if severity == 'High' else '#FFFFE0' if severity == 'Medium' else '#E0FFFF'}; padding: 10px; border-radius: 5px; margin-bottom: 10px;">
                                            <p style="font-weight: bold;">🚨 {issue}</p>
                                            <p>💡 Suggestion: {suggestion}</p>
                                        </div>
                                        """, unsafe_allow_html=True)

                    st.markdown("---")

        except Exception as e:
            st.error(f"An error occurred while processing the input: {str(e)}")

    st.sidebar.title("About")
    st.sidebar.info(
        "This app analyzes AWS Security Group configurations for potential security issues. "
        "It checks for overly permissive rules, large port ranges, and use of the default security group."
    )

if __name__ == "__main__":
    main()