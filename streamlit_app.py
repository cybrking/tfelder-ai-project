def main():
    st.set_page_config(layout="wide")
    st.title("Security Group Configuration Analyzer")

    uploaded_file = st.file_uploader("Choose a security group configuration file", type=["json"])
    
    if uploaded_file is not None:
        file_contents = uploaded_file.getvalue().decode("utf-8")
        
        # Debug information
        st.subheader("Debug Information")
        st.text("File contents:")
        st.code(file_contents)

        try:
            sg_configs = parse_security_groups(file_contents)
            
            if sg_configs is None:
                st.error("Failed to parse security groups. Please check the file format and try again.")
                return

            st.success(f"Successfully parsed {len(sg_configs)} security group(s)")

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

            # Comparison (if multiple security groups)
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
        except Exception as e:
            st.error(f"An unexpected error occurred: {str(e)}")

if __name__ == "__main__":
    main()