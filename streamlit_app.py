import streamlit as st
import json
from collections import defaultdict
import pandas as pd

# ... [Keep the existing helper functions: parse_security_groups, is_port_sensitive, is_large_port_range, analyze_security_group, create_rules_dataframe] ...

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