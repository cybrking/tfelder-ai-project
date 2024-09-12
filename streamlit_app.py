import streamlit as st
import json
from collections import defaultdict
import plotly.graph_objects as go
import base64
import io
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import networkx as nx

# ... [previous functions remain unchanged] ...

# Add the create_network_diagram function here

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
                        if issues.get(severity):
                            st.metric(f"{severity} Severity Issues", len(issues[severity]))

                st.subheader("Detailed Analysis Results")
                for severity in ["High", "Medium", "Low"]:
                    if issues.get(severity):
                        with st.expander(f"{severity} Severity Issues", expanded=(severity == "High")):
                            for issue, suggestion in zip(issues[severity], suggestions[severity]):
                                st.warning(issue)
                                st.info(f"Suggestion: {suggestion}")
                                st.markdown("---")

                if not any(issues.values()):
                    st.success("No security issues found.")

                st.subheader("Security Group Network Diagram")
                network_fig = create_network_diagram(sg_config)
                st.plotly_chart(network_fig, use_container_width=True)

                st.subheader("Security Group Rules Table")
                rules_fig = visualize_security_group(sg_config)
                st.plotly_chart(rules_fig, use_container_width=True)

            # ... [rest of the main function remains unchanged] ...

if __name__ == "__main__":
    main()