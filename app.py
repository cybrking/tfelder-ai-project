import streamlit as st
from pages.analyzer import security_group_analyzer_page
from pages.about import about_page

def main():
    st.set_page_config(layout="wide", page_title="Security Group Analyzer")

    # Sidebar for navigation
    st.sidebar.title("Navigation")
    page = st.sidebar.radio("Go to", ("Security Group Analyzer", "About"))

    if page == "Security Group Analyzer":
        security_group_analyzer_page()
    elif page == "About":
        about_page()

if __name__ == "__main__":
    main()