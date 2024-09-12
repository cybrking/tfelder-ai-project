import streamlit as st
import json
from collections import defaultdict
import pandas as pd
import plotly.graph_objects as go
import networkx as nx
import base64
import boto3
from datetime import datetime
import io
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

# AWS Integration
def get_aws_security_groups():
    try:
        session = boto3.Session()
        ec2 = session.client('ec2')
        response = ec2.describe_security_groups()
        return response['SecurityGroups']
    except Exception as e:
        st.error(f"Error fetching AWS security groups: {str(e)}")
        return None

# Enhanced Parsing
def parse_security_groups(file_contents=None, aws_groups=None):
    if file_contents:
        try:
            data = json.loads(file_contents)
            return data if isinstance(data, list) else [data]
        except json.JSONDecodeError:
            st.error("Invalid JSON file. Please upload a valid security group configuration.")
            return None
    elif aws_groups:
        return aws_groups
    else:
        st.error("No security group data provided.")
        return None

# Enhanced Analysis
def analyze_security_group(sg_config):
    issues = defaultdict(list)
    suggestions = defaultdict(list)
    unused_rules = []

    inbound_rules = sg_config.get("IpPermissions", [])
    outbound_rules = sg_config.get("IpPermissionsEgress", [])

    # Existing checks...

    # New check for rule consolidation
    consolidation_opportunities = identify_consolidation_opportunities(inbound_rules + outbound_rules)
    if consolidation_opportunities:
        issues["Low"].extend(consolidation_opportunities)
        suggestions["Low"].extend(["Consider consolidating these rules to improve efficiency and readability"] * len(consolidation_opportunities))

    return issues, suggestions

def identify_consolidation_opportunities(rules):
    # Implementation of rule consolidation logic
    # This is a simplified version and might need to be expanded based on specific requirements
    opportunities = []
    for i, rule1 in enumerate(rules):
        for j, rule2 in enumerate(rules[i+1:], start=i+1):
            if rule1['IpProtocol'] == rule2['IpProtocol'] and rule1['FromPort'] == rule2['FromPort'] and rule1['ToPort'] == rule2['ToPort']:
                opportunities.append(f"Rules {i} and {j} have the same protocol and port range and could potentially be consolidated")
    return opportunities

# Advanced Visualization
def visualize_security_group(sg_config):
    G = nx.Graph()
    
    def add_rules_to_graph(rules, direction):
        for i, rule in enumerate(rules):
            rule_node = f"{direction}_rule_{i}"
            G.add_node(rule_node, label=f"{rule['IpProtocol']} {rule['FromPort']}-{rule['ToPort']}")
            G.add_edge("Security Group", rule_node)
            for ip_range in rule.get('IpRanges', []):
                cidr = ip_range['CidrIp']
                G.add_node(cidr, label=cidr)
                G.add_edge(rule_node, cidr)

    G.add_node("Security Group", label=sg_config.get('GroupName', 'Security Group'))
    add_rules_to_graph(sg_config.get('IpPermissions', []), 'inbound')
    add_rules_to_graph(sg_config.get('IpPermissionsEgress', []), 'outbound')

    pos = nx.spring_layout(G)
    edge_x, edge_y = [], []
    for edge in G.edges():
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])

    edge_trace = go.Scatter(
        x=edge_x, y=edge_y,
        line=dict(width=0.5, color='#888'),
        hoverinfo='none',
        mode='lines')

    node_x, node_y = [], []
    for node in G.nodes():
        x, y = pos[node]
        node_x.append(x)
        node_y.append(y)

    node_trace = go.Scatter(
        x=node_x, y=node_y,
        mode='markers+text',
        hoverinfo='text',
        marker=dict(
            showscale=True,
            colorscale='YlGnBu',
            size=10,
            colorbar=dict(
                thickness=15,
                title='Node Connections',
                xanchor='left',
                titleside='right'
            ),
            line_width=2))

    node_adjacencies = []
    node_text = []
    for node, adjacencies in enumerate(G.adjacency()):
        node_adjacencies.append(len(adjacencies[1]))
        node_text.append(f"{G.nodes[adjacencies[0]]['label']} # of connections: {len(adjacencies[1])}")

    node_trace.marker.color = node_adjacencies
    node_trace.text = node_text

    fig = go.Figure(data=[edge_trace, node_trace],
                    layout=go.Layout(
                        title='Security Group Network Diagram',
                        titlefont_size=16,
                        showlegend=False,
                        hovermode='closest',
                        margin=dict(b=20,l=5,r=5,t=40),
                        annotations=[ dict(
                            showarrow=False,
                            xref="paper", yref="paper",
                            x=0.005, y=-0.002 ) ],
                        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False))
                    )
    return fig

# Comparison Functionality
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

# Custom Rule Checks
def custom_rule_check(sg_config, custom_rules):
    custom_issues = []
    for rule in custom_rules:
        if eval(rule, {'sg_config': sg_config}):
            custom_issues.append(f"Custom rule violated: {rule}")
    return custom_issues

# Enhanced Export Functionality
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

# Historical Analysis
def track_changes(sg_config, historical_data):
    changes = []
    if historical_data:
        last_config = historical_data[-1]
        changes = compare_security_groups(last_config, sg_config)
    return changes

# Main Streamlit App
def main():
    st.set_page_config(layout="wide")
    st.title("Comprehensive Security Group Configuration Analyzer")

    # Data Source Selection
    data_source = st.radio("Select data source:", ("Upload JSON", "Fetch from AWS"))

    if data_source == "Upload JSON":
        uploaded_file = st.file_uploader("Choose a security group configuration file", type=["json"])
        if uploaded_file is not None:
            file_contents = uploaded_file.getvalue().decode("utf-8")
            sg_configs = parse_security_groups(file_contents=file_contents)
    else:
        aws_groups = get_aws_security_groups()
        sg_configs = parse_security_groups(aws_groups=aws_groups)

    if sg_configs:
        all_issues = []
        all_suggestions = []
        
        # Custom Rule Input
        custom_rules = st.text_area("Enter custom rules (Python expressions):", 
                                    "sg_config.get('GroupName', '') == 'default'")
        custom_rules = [rule.strip() for rule in custom_rules.split('\n') if rule.strip()]
        
        for i, sg_config in enumerate(sg_configs):
            st.subheader(f"Security Group {i+1}: {sg_config.get('GroupName', 'Unnamed')}")
            
            col1, col2 = st.columns(2)
            with col1:
                st.json(sg_config)

            issues, suggestions = analyze_security_group(sg_config)
            custom_issues = custom_rule_check(sg_config, custom_rules)
            issues['Custom'] = custom_issues
            suggestions['Custom'] = ["Review and adjust according to your security policies"] * len(custom_issues)
            
            all_issues.append(issues)
            all_suggestions.append(suggestions)
            
            with col2:
                st.subheader("Analysis Summary")
                total_issues = sum(len(issues[severity]) for severity in issues)
                st.metric("Total Issues", total_issues)
                
                for severity in ["High", "Medium", "Low", "Custom"]:
                    st.metric(f"{severity} Severity Issues", len(issues[severity]))

            st.subheader("Detailed Analysis Results")
            for severity in ["High", "Medium", "Low", "Custom"]:
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

        # Historical Analysis
        st.subheader("Historical Analysis")
        if st.button("Track Changes"):
            # In a real application, you would store and retrieve historical data from a database
            # For this example, we'll just compare the current config to itself
            changes = track_changes(sg_configs[0], [sg_configs[0]])
            if changes:
                for change in changes:
                    st.write(change)
            else:
                st.write("No changes detected.")

if __name__ == "__main__":
    main()