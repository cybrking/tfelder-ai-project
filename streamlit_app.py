import streamlit as st
import json
from collections import defaultdict
import plotly.graph_objects as go
import base64
import io
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

def parse_security_groups(file_contents):
    try:
        data = json.loads(file_contents)
        return data if isinstance(data, list) else [data]
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

def compare_security_groups(sg1, sg2):
    differences = []
    
    def compare_rules(rules1, rules2, direction):
        for i, rule1 in enumerate(rules1):
            if i >= len(rules2) or rule1 != rules2[i]:
                differences.append(f"Difference in {direction} rule {i}")
        if len(rules1) < len(rules2):
            differences.append(f"Additional {direction} rules in second group")

    compare_rules(sg1.get('IpPermissions', []), sg2.get('IpPermissions', []), 'inbound')
    compare_rules(sg1.get('IpPermissionsEgress', []), sg2.get('IpPermissionsEgress', []), 'outbound')
    
    return differences

def export_report(sg_configs, all_issues, all_suggestions, format='txt'):
    if format == 'txt':
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
    elif format == 'pdf':
        buffer = io.BytesIO()
        c = canvas.Canvas(buffer, pagesize=letter)
        width, height = letter
        c.setFont("Helvetica", 12)
        y = height - 40
        for i, sg_config in enumerate(sg_configs):
            c.drawString(50, y, f"Security Group {i+1}: {sg_config.get('GroupName', 'Unnamed')}")
            y -= 20
            issues = all_issues[i]
            suggestions = all_suggestions[i]
            for severity in ["High", "Medium", "Low"]:
                if issues[severity]:
                    c.drawString(50, y, f"{severity} Severity Issues:")
                    y -= 15
                    for issue, suggestion in zip(issues[severity], suggestions[severity]):
                        c.drawString(70, y, f"- Issue: {issue}")
                        y -= 15
                        c.drawString(90, y, f"Suggestion: {suggestion}")
                        y -= 20
                if y < 50:
                    c.showPage()
                    y = height - 40
            c.showPage()
        c.save()
        buffer.seek(0)
        return buffer
    else:
        raise ValueError("Unsupported export format")

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

            # Comparison
            if len(sg_configs) > 1:
                st.subheader("Security Group Comparison")
                sg1 = st.selectbox("Select first security group", range(len(sg_configs)), format_func=lambda i: sg_configs[i].get('GroupName', f'Security Group {i+1}'))
                sg2 = st.selectbox("Select second security group", range(len(sg_configs)), format_func=lambda i: sg_configs[i].get('GroupName', f'Security Group {i+1}'))
                if st.button("Compare"):
                    differences = compare_security_groups(sg_configs[sg1], sg_configs[sg2])
                    if differences:
                        for diff in differences:
                            st.write(diff)
                    else:
                        st.write("No differences found.")

            # Export
            st.subheader("Export Report")
            export_format = st.radio("Select export format:", ("TXT", "PDF"))
            if st.button("Generate Report"):
                if export_format == "TXT":
                    report = export_report(sg_configs, all_issues, all_suggestions, format='txt')
                    b64 = base64.b64encode(report.encode()).decode()
                    href = f'<a href="data:file/txt;base64,{b64}" download="security_group_analysis_report.txt">Download TXT Report</a>'
                    st.markdown(href, unsafe_allow_html=True)
                else:
                    pdf_buffer = export_report(sg_configs, all_issues, all_suggestions, format='pdf')
                    b64 = base64.b64encode(pdf_buffer.getvalue()).decode()
                    href = f'<a href="data:application/pdf;base64,{b64}" download="security_group_analysis_report.pdf">Download PDF Report</a>'
                    st.markdown(href, unsafe_allow_html=True)

if __name__ == "__main__":
    main()