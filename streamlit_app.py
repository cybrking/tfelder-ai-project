import streamlit as st
import json
from collections import defaultdict
import plotly.graph_objects as go
import base64
import io
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import networkx as nx

def parse_security_groups(file_contents):
    try:
        data = json.loads(file_contents)
        if isinstance(data, dict):
            # Single security group
            return [data]
        elif isinstance(data, list):
            # Multiple security groups
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

def analyze_security_group(sg_config):
    issues = defaultdict(list)
    suggestions = defaultdict(list)
    unused_rules = []

    inbound_rules = sg_config.get("IpPermissions", [])
    outbound_rules = sg_config.get("IpPermissionsEgress", [])

    # Check inbound rules
    for rule in inbound_rules:
        protocol = rule.get("IpProtocol")
        from_port = rule.get("FromPort")
        to_port = rule.get("ToPort")

        if not rule.get("IpRanges") and not rule.get("UserIdGroupPairs"):
            unused_rules.append(f"Inbound: {protocol} {from_port}-{to_port}")

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
    for rule in outbound_rules:
        if rule.get("IpProtocol") == "-1" and rule.get("FromPort") == -1 and rule.get("ToPort") == -1:
            for ip_range in rule.get("IpRanges", []):
                if ip_range.get("CidrIp") == "0.0.0.0/0":
                    issues["Low"].append("All outbound traffic is allowed")
                    suggestions["Low"].append("Consider restricting outbound traffic to necessary destinations and ports")

    if unused_rules:
        issues["Low"].extend([f"Unused rule: {rule}" for rule in unused_rules])
        suggestions["Low"].extend(["Remove unused rule to improve security posture" for _ in unused_rules])

    return issues, suggestions

def visualize_security_group(sg_config):
    def create_rule_text(rule):
        protocol = rule.get("IpProtocol")
        from_port = rule.get("FromPort")
        to_port = rule.get("ToPort")
        cidrs = [ip_range.get("CidrIp") for ip_range in rule.get("IpRanges", [])]
        return f"{protocol} {from_port}-{to_port} from {', '.join(cidrs)}"

    inbound_rules = [create_rule_text(rule) for rule in sg_config.get("IpPermissions", [])]
    outbound_rules = [create_rule_text(rule) for rule in sg_config.get("IpPermissionsEgress", [])]

    fig = go.Figure(data=[go.Table(
        header=dict(values=["Inbound Rules", "Outbound Rules"]),
        cells=dict(values=[inbound_rules, outbound_rules])
    )])

    fig.update_layout(title="Security Group Rules Visualization")
    return fig

def create_network_diagram(sg_config):
    G = nx.Graph()
    
    # Add the security group as the central node
    sg_name = sg_config.get('GroupName', 'Security Group')
    G.add_node(sg_name, node_type='security_group')
    
    # Process inbound rules
    for i, rule in enumerate(sg_config.get('IpPermissions', [])):
        protocol = rule.get('IpProtocol', 'All')
        from_port = rule.get('FromPort', 'Any')
        to_port = rule.get('ToPort', 'Any')
        
        for ip_range in rule.get('IpRanges', []):
            cidr = ip_range.get('CidrIp', 'Unknown')
            node_name = f"In: {cidr}"
            G.add_node(node_name, node_type='cidr')
            G.add_edge(node_name, sg_name, 
                       label=f"{protocol}: {from_port}-{to_port}",
                       direction='inbound')
    
    # Process outbound rules
    for i, rule in enumerate(sg_config.get('IpPermissionsEgress', [])):
        protocol = rule.get('IpProtocol', 'All')
        from_port = rule.get('FromPort', 'Any')
        to_port = rule.get('ToPort', 'Any')
        
        for ip_range in rule.get('IpRanges', []):
            cidr = ip_range.get('CidrIp', 'Unknown')
            node_name = f"Out: {cidr}"
            G.add_node(node_name, node_type='cidr')
            G.add_edge(sg_name, node_name, 
                       label=f"{protocol}: {from_port}-{to_port}",
                       direction='outbound')
    
    # Create the Plotly figure
    pos = nx.spring_layout(G)
    edge_x = []
    edge_y = []
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

    node_x = []
    node_y = []
    for node in G.nodes():
        x, y = pos[node]
        node_x.append(x)
        node_y.append(y)

    node_trace = go.Scatter(
        x=node_x, y=node_y,
        mode='markers',
        hoverinfo='text',
        marker=dict(
            showscale=True,
            colorscale='YlGnBu',
            size=10,
            color=[],
            line_width=2))

    # Color nodes by type
    color_map = {'security_group': 0, 'cidr': 1}
    node_colors = [color_map[G.nodes[node]['node_type']] for node in G.nodes()]
    node_trace.marker.color = node_colors

    # Add node labels
    node_text = list(G.nodes())
    node_trace.text = node_text

    # Add edge labels
    annotations = []
    for edge in G.edges(data=True):
        start = pos[edge[0]]
        end = pos[edge[1]]
        x = (start[0] + end[0]) / 2
        y = (start[1] + end[1]) / 2
        annotations.append(dict(
            x=x, y=y,
            xref="x", yref="y",
            text=edge[2]['label'],
            showarrow=False,
            font=dict(size=8),
            bgcolor="white",
            bordercolor="black",
            borderwidth=1
        ))

    fig = go.Figure(data=[edge_trace, node_trace],
             layout=go.Layout(
                title='Security Group Network Diagram',
                titlefont_size=16,
                showlegend=False,
                hovermode='closest',
                margin=dict(b=20,l=5,r=5,t=40),
                annotations=annotations,
                xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                yaxis=dict(showgrid=False, zeroline=False, showticklabels=False))
                )
    
    return fig

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
                sg1 = st.selectbox("Select first security group", range(len(sg_configs)), format_func=lambda i: sg_configs[i].get('GroupName))