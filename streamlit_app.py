import streamlit as st
import json

def parse_security_group(file_contents):
    try:
        return json.loads(file_contents)
    except json.JSONDecodeError:
        st.error("Invalid JSON file. Please upload a valid security group configuration.")
        return None

def analyze_security_group(sg_config):
    issues = []

    # Check for overly permissive inbound rules
    for rule in sg_config.get("IpPermissions", []):
        for ip_range in rule.get("IpRanges", []):
            if ip_range.get("CidrIp") == "0.0.0.0/0":
                issues.append(f"Overly permissive inbound rule: {rule.get('IpProtocol')} {rule.get('FromPort')}-{rule.get('ToPort')} open to the world")

    # Check for overly permissive outbound rules
    for rule in sg_config.get("IpPermissionsEgress", []):
        if rule.get("IpProtocol") == "-1" and rule.get("FromPort") == -1 and rule.get("ToPort") == -1:
            for ip_range in rule.get("IpRanges", []):
                if ip_range.get("CidrIp") == "0.0.0.0/0":
                    issues.append("All outbound traffic is allowed. Consider restricting this for better security.")

    # Check for open SSH access
    for rule in sg_config.get("IpPermissions", []):
        if rule.get("FromPort") == 22 and rule.get("ToPort") == 22:
            for ip_range in rule.get("IpRanges", []):
                if ip_range.get("CidrIp") == "0.0.0.0/0":
                    issues.append("SSH (port 22) is open to the world. Consider restricting this to specific IP ranges.")

    return issues

def main():
    st.title("Security Group Configuration Analyzer")

    uploaded_file = st.file_uploader("Choose a security group configuration file", type=["json"])

    if uploaded_file is not None:
        file_contents = uploaded_file.getvalue().decode("utf-8")
        st.text("File contents:")
        st.code(file_contents)

        sg_config = parse_security_group(file_contents)
        if sg_config:
            issues = analyze_security_group(sg_config)
            
            st.subheader("Analysis Results")
            if issues:
                for issue in issues:
                    st.warning(issue)
            else:
                st.success("No major security issues found.")

if __name__ == "__main__":
    main()