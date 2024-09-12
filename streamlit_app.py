import streamlit as st
import yaml
import json

def main():
    st.title("Security Group Configuration Analyzer")

    uploaded_file = st.file_uploader("Choose a security group configuration file", type=["yaml", "json"])

    if uploaded_file is not None:
        file_contents = uploaded_file.read().decode("utf-8")
        st.text("File contents:")
        st.code(file_contents)

if __name__ == "__main__":
    main()