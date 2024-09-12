import streamlit as st

def about_page():
    st.title("About AWS Security Group Analyzer")
    st.write("""
    This application is designed to analyze AWS Security Group configurations for potential security issues. 
    It checks for:
    
    - Overly permissive rules
    - Large port ranges
    - Use of the default security group
    
    The analyzer helps identify potential vulnerabilities in your AWS security group configurations, 
    allowing you to make informed decisions about your cloud security posture.
    
    To use the analyzer:
    1. Prepare your AWS Security Group configuration in JSON format.
    2. Upload the JSON file on the Analyzer page.
    3. Review the analysis results and suggested improvements.
    
    Remember, this tool is meant to assist in identifying potential issues, but it's not a substitute for 
    comprehensive security audits or professional security advice.
    """)