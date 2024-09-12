import streamlit as st
import json
from collections import defaultdict

def parse_security_group(file_contents):
    try:
        return json.loads(file_contents)
    except json.JSONDecodeError:
        st.error("Invalid JSON file. Please upload a valid security group configuration.")
        return None

def analyze_security_group(sg_config):
    issues = defaultdict(list)
    suggestions = defaultdict(list)

    # Check inbound rules
    for rule in sg_config.get("IpPermissions", []):
        protocol = rule.get("IpProtocol")
        from_port = rule.get("FromPort")
        to_port = rule.get("ToPort")

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
    for rule in sg_config.get("IpPermissionsEgress", []):
        if rule.get("IpProtocol") == "-1" and rule.get("FromPort") == -1 and rule.get("ToPort") == -1:
            for ip_range in rule.get("IpRanges", []):
                if ip_range.get("CidrIp") == "0.0.0.0/0":
                    issues["Low"].append("All outbound traffic is allowed")
                    suggestions["Low"].append("Consider restricting outbound traffic to necessary destinations and ports")

    return issues, suggestions

def main():
    st.set_page_config(layout="wide")
    st.title("Security Group Configuration Analyzer")

    uploaded_file = st.file_uploader("Choose a security group configuration file", type=["json"])

    if uploaded_file is not None:
        file_contents = uploaded_file.getvalue().decode("utf-8")
        
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("File contents:")
            st.code(file_contents)

        sg_config = parse_security_group(file_contents)
        if sg_config:
            issues, suggestions = analyze_security_group(sg_config)
            
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

if __name__ == "__main__":
    main()