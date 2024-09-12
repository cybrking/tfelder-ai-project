import streamlit as st
import json
from collections import defaultdict
import plotly.graph_objects as go
import networkx as nx
import pandas as pd

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

def is_port_sensitive(port):
    sensitive_ports = [22, 3389, 1433, 3306, 5432, 27017, 6379, 9200, 9300]
    return port in sensitive_ports

def is_large_port_range(from_port, to_port):
    return to_port - from_port > 100

def analyze_security_group(sg_config):
    issues = defaultdict(list)
    suggestions = defaultdict(list)
    
    inbound_rules = sg_config.get("IpPermissions", [])
    outbound_rules = sg_config.get("IpPermissionsEgress", [])

    # Check for overly permissive rules
    for rule in inbound_rules + outbound_rules:
        protocol = rule.get("IpProtocol")
        from_port = rule.get("FromPort")
        to_port = rule.get("ToPort")
        
        for ip_range in rule.get("IpRanges", []):
            cidr = ip_range.get("CidrIp")
            if cidr == "0.0.0.0/0":
                if protocol == "-1":
                    issues["High"].append(f"Overly permissive rule: All traffic allowed from {cidr}")
                    suggestions["High"].append("Restrict traffic to only necessary protocols and ports")
                elif is_port_sensitive(from_port) or is_port_sensitive(to_port):
                    issues["High"].append(f"Overly permissive rule: {protocol} {from_port}-{to_port} open to the world")
                    suggestions["High"].append(f"Restrict {protocol} {from_port}-{to_port} to specific IP ranges or security groups")
                else:
                    issues["Medium"].append(f"Potentially overly permissive rule: {protocol} {from_port}-{to_port} open to the world")
                    suggestions["Medium"].append(f"Consider restricting {protocol} {from_port}-{to_port} to specific IP ranges or security groups")

    # Check for large port ranges
    for rule in inbound_rules + outbound_rules:
        from_port = rule.get("FromPort")
        to_port = rule.get("ToPort")
        if from_port is not None and to_port is not None and is_large_port_range(from_port, to_port):
            issues["Medium"].append(f"Large port range: {from_port}-{to_port}")
            suggestions["Medium"].append(f"Consider narrowing the port range {from_port}-{to_port} to only necessary ports")

    # Check for rule duplication
    rule_set = set()
    for rule in inbound_rules + outbound_rules:
        rule_tuple = (
            rule.get("IpProtocol"),
            rule.get("FromPort"),
            rule.get("ToPort"),
            frozenset((ip_range.get("CidrIp") for ip_range in rule.get("IpRanges", [])))
        )
        if rule_tuple in rule_set:
            issues["Low"].append(f"Duplicate rule: {rule}")
            suggestions["Low"].append("Remove duplicate rule to simplify security group configuration")
        else:
            rule_set.add(rule_tuple)

    # Check if it's the default security group
    if sg_config.get("GroupName") == "default":
        issues["Medium"].append("Default security group is being used")
        suggestions["Medium"].append("Consider creating custom security groups instead of using the default group")

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

    df = pd.DataFrame({
        "Inbound Rules": inbound_rules + [""] * (len(outbound_rules) - len(inbound_rules)),
        "Outbound Rules": outbound_rules + [""] * (len(inbound_rules) - len(outbound_rules))
    })

    fig = go.Figure(data=[go.Table(
        header=dict(values=list(df.columns),
                    fill_color='#0083B8',
                    align='left',
                    font=dict(color='white', size=12)),
        cells=dict(values=[df["Inbound Rules"], df["Outbound Rules"]],
                   fill_color='#F0F2F6',
                   align='left'))
    ])

    fig.update_layout(
        title="Security Group Rules",
        font=dict(family="Arial", size=14),
        margin=dict(l=0, r=0, t=40, b=0)
    )

    return fig

def create_network_diagram(sg_config):
    G = nx.Graph()
    sg_name = sg_config.get('GroupName', 'Security Group')
    G.add_node(sg_name, node_type='security_group')
    
    for direction, rules in [('Inbound', sg_config.get('IpPermissions', [])),
                             ('Outbound', sg_config.get('IpPermissionsEgress', []))]:
        for rule in rules:
            protocol = rule.get('IpProtocol', 'All')
            from_port = rule.get('FromPort', 'Any')
            to_port = rule.get('ToPort', 'Any')
            
            for ip_range in rule.get('IpRanges', []):
                cidr = ip_range.get('CidrIp', 'Unknown')
                node_name = f"{direction}: {cidr}"
                G.add_node(node_name, node_type='cidr')
                G.add_edge(sg_name, node_name, 
                           label=f"{protocol}: {from_port}-{to_port}",
                           direction=direction.lower())
    
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
        mode='markers',
        hoverinfo='text',
        marker=dict(
            showscale=True,
            colorscale='YlGnBu',
            size=10,
            color=[],
            line_width=2))

    color_map = {'security_group': 0, 'cidr': 1}
    node_colors = [color_map[G.nodes[node]['node_type']] for node in G.nodes()]
    node_trace.marker.color = node_colors
    node_trace.text = list(G.nodes())

    fig = go.Figure(data=[edge_trace, node_trace],
             layout=go.Layout(
                title='Security Group Network Diagram',
                titlefont_size=16,
                showlegend=False,
                hovermode='closest',
                margin=dict(b=20,l=5,r=5,t=40),
                annotations=[dict(
                    text="",
                    showarrow=False,
                    xref="paper", yref="paper",
                    x=0.005, y=-0.002)],
                xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                yaxis=dict(showgrid=False, zeroline=False, showticklabels=False))
                )
    
    return fig

def main():
    st.set_page_config(layout="wide", page_title="Security Group Analyzer")

    st.markdown("""
    <style>
    .main {
        background-color: #f0f2f6;
    }
    .stApp {
        max-width: 1200px;
        margin: 0 auto;
    }
    .st-bx {
        background-color: #ffffff;
        border-radius: 5px;
        padding: 20px;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
    }
    .st-emotion-cache-1wbqy5j {
        max-width: 1200px;
    }
    </style>
    """, unsafe_allow_html=True)

    st.title("🛡️ AWS Security Group Analyzer")

    uploaded_file = st.file_uploader("Choose a security group configuration file", type=["json"])
    
    if uploaded_file is not None:
        try:
            file_contents = uploaded_file.getvalue().decode("utf-8")
            sg_configs = parse_security_groups(file_contents)
            
            if sg_configs:
                for i, sg_config in enumerate(sg_configs):
                    st.markdown(f"## Security Group: {sg_config.get('GroupName', 'Unnamed')}")
                    
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.markdown("### 📊 Rules Visualization")
                        fig = visualize_security_group(sg_config)
                        st.plotly_chart(fig, use_container_width=True)

                    with col2:
                        st.markdown("### 🕸️ Network Diagram")
                        net_fig = create_network_diagram(sg_config)
                        st.plotly_chart(net_fig, use_container_width=True)

                    issues, suggestions = analyze_security_group(sg_config)
                    
                    st.markdown("### 🔍 Analysis Results")
                    
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
            st.error(f"An error occurred while processing the file: {str(e)}")

    st.sidebar.title("About")
    st.sidebar.info(
        "This app analyzes AWS Security Group configurations for potential security issues. "
        "It checks for overly permissive rules, large port ranges, rule duplication, "
        "and use of the default security group."
    )

if __name__ == "__main__":
    main()