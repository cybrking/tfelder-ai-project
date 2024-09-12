import streamlit as st
import json
from collections import defaultdict
import pandas as pd
import plotly.graph_objects as go
import base64

def parse_security_groups(file_contents):
    try:
        data = json.loads(file_contents)
        if isinstance(data, list):
            return data
        else:
            return [data]
    except json.JSONDecodeError:
        st.error("Invalid JSON file. Please upload a valid security group configuration.")
        return None

def analyze_security_group(sg_config):
    issues = defaultdict(list)
    suggestions = defaultdict(list)
    unused_rules = []

    inbound_rules = sg_config.get("IpPermissions", [])
    outbound_rules = sg_config.get("IpPermissionsEgress", [])

    # Check inbound rules
    for rule in inbound_rules:
        protocol = rule.get("IpProtocol")
        from_port = rule.get("FromPort")
        to_port = rule.get("ToPort")

        if not rule.get("IpRanges") and not rule.get("UserIdGroupPairs"):
            unused_rules.append(f"Inbound: {protocol} {from_port}-{to_port}")

        for ip_range in rule.get("IpRanges", []):
            cidr = ip_range.get("CidrIp")

            if cidr == "0.0.0.0/0":
                issues["High"].append(f"Overly permissive inbound rule: {protocol} {from_port}-{to_port} open to the world")
                suggestions["High"].append(f"Restrict {protocol} {from_port}-{to_port} to specific IP ranges or security groups")

            if protocol == "tcp" and from_port == 22 and to_port == 22:
                if cidr == "0.0.0.0/0":
                    issues["High"].append("SSH (port 22) is open to the world")
                    suggestions["High"].append("Restrict SSH access to specific IP ranges or use a bastion host")
                else:
                    issues["Low"].append(f"SSH (port 22) is open to {cidr}")
                    suggestions["Low"].append("Consider using SSH keys instead of passwords and implement multi-factor authentication")

            if protocol == "-1" and from_port == -1 and to_port == -1:
                issues["Medium"].append(f"All traffic allowed from {cidr}")
                suggestions["Medium"].append(f"Restrict traffic from {cidr} to only necessary protocols and ports")

    # Check outbound rules
    for rule in outbound_rules:
        if rule.get("IpProtocol") == "-1" and rule.get("FromPort") == -1 and rule.get("ToPort") == -1:
            for ip_range in rule.get("IpRanges", []):
                if ip_range.get("CidrIp") == "0.0.0.0/0":
                    issues["Low"].append("All outbound traffic is allowed")
                    suggestions["Low"].append("Consider restricting outbound traffic to necessary destinations and ports")

    if unused_rules:
        issues["Low"].extend([f"Unused rule: {rule}" for rule in unused_rules])
        suggestions["Low"].extend(["Remove unused rule to improve security posture" for _ in unused_rules])

    return issues, suggestions

def visualize_security_group(sg_config):
    inbound_rules = sg_config.get("IpPermissions", [])
    outbound_rules = sg_config.get("IpPermissionsEgress", [])

    def create_rule_text(rule):
        protocol = rule.get("IpProtocol")
        from_port = rule.get("FromPort")
        to_port = rule.get("ToPort")
        cidrs = [ip_range.get("CidrIp") for ip_range in rule.get("IpRanges", [])]
        return f"{protocol} {from_port}-{to_port} from {', '.join(cidrs)}"

    inbound_texts = [create_rule_text(rule) for rule in inbound_rules]
    outbound_texts = [create_rule_text(rule) for rule in outbound_rules]

    fig = go.Figure()

    fig.add_trace(go.Table(
        header=dict(values=["Inbound Rules", "Outbound Rules"]),
        cells=dict(values=[inbound_texts, outbound_texts])
    ))

    fig.update_layout(title="Security Group Rules Visualization")
    return fig

def export_report(sg_configs, all_issues, all_suggestions):
    report = "Security Group Analysis Report\n\n"
    for i, sg_config in enumerate(sg_configs):
        report += f"Security Group {i+1}: {sg_config.get('GroupName', 'Unnamed')}\n"
        report += "=" * 50 + "\n\n"
        
        issues = all_issues[i]
        suggestions = all_suggestions[i]
        
        for severity in ["High", "Medium", "Low"]:
            if issues[severity]:
                report += f"{severity} Severity Issues:\n"
                for issue, suggestion in zip(issues[severity], suggestions[severity]):
                    report += f"- Issue: {issue}\n"
                    report += f"  Suggestion: {suggestion}\n"
                report += "\n"
        
        report += "\n\n"
    
    return report

def get_table_download_link(text):
    b64 = base64.b64encode(text.encode()).decode()
    return f'<a href="data:file/txt;base64,{b64}" download="security_group_analysis_report.txt">Download Report</a>'

def main():
    st.set_page_config(layout="wide")
    st.title("Security Group Configuration Analyzer")

    uploaded_file = st.file_uploader("Choose a security group configuration file", type=["json"])

    if uploaded_file is not None:
        file_contents = uploaded_file.getvalue().decode("utf-8")
        
        sg_configs = parse_security_groups(file_contents)
        if sg_configs:
            all_issues = []
            all_suggestions = []
            
            for i, sg_config in enumerate(sg_configs):
                st.subheader(f"Security Group {i+1}: {sg_config.get('GroupName', 'Unnamed')}")
                
                col1, col2 = st.columns(2)
                with col1:
                    st.json(sg_config)

                issues, suggestions = analyze_security_group(sg_config)
                all_issues.append(issues)
                all_suggestions.append(suggestions)
                
                with col2:
                    st.subheader("Analysis Summary")
                    total_issues = sum(len(issues[severity]) for severity in issues)
                    st.metric("Total Issues", total_issues)
                    
                    for severity in ["High", "Medium", "Low"]:
                        st.metric(f"{severity} Severity Issues", len(issues[severity]))

                st.subheader("Detailed Analysis Results")
                for severity in ["High", "Medium", "Low"]:
                    if issues[severity]:
                        with st.expander(f"{severity} Severity Issues", expanded=(severity == "High")):
                            for issue, suggestion in zip(issues[severity], suggestions[severity]):
                                st.warning(issue)
                                st.info(f"Suggestion: {suggestion}")
                                st.markdown("---")

                if not any(issues.values()):
                    st.success("No security issues found.")

                st.subheader("Security Group Rules Visualization")
                fig = visualize_security_group(sg_config)
                st.plotly_chart(fig)

            report = export_report(sg_configs, all_issues, all_suggestions)
            st.markdown(get_table_download_link(report), unsafe_allow_html=True)

if __name__ == "__main__":
    main()