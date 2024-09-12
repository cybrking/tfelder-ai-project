import json
import streamlit as st

def parse_security_groups(file_contents):
    try:
        data = json.loads(file_contents)
        if isinstance(data, dict):
            return [data]
        elif isinstance(data, list):
            return data
        else:
            st.error(f"Invalid JSON structure. Expected a dictionary or a list of dictionaries. Got: {type(data)}")
            return None
    except json.JSONDecodeError as e:
        st.error(f"Invalid JSON file: {str(e)}")
        return None
    except Exception as e:
        st.error(f"An unexpected error occurred while parsing the security groups: {str(e)}")
        return None