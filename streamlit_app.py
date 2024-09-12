import streamlit as st
import json
from collections import defaultdict
import plotly.graph_objects as go
import networkx as nx
import pandas as pd
import plotly.express as px
from streamlit_agGrid import AgGrid
from streamlit_agGrid import GridOptionsBuilder
import altair as alt

# ... [Keep existing helper functions: parse_security_groups, is_port_sensitive, is_large_port_range, analyze_security_group] ...

def create_enhanced_dataframe(sg_config):
    inbound_rules = sg_config.get("IpPermissions", [])
    outbound_rules = sg_config.get("IpPermissionsEgress", [])
    
    def create_rule_df(rules, direction):
        data = []
        for rule in rules:
            protocol = rule.get("IpProtocol", "All")
            from_port = rule.get("FromPort", "Any")
            to_port = rule.get("ToPort", "Any")
            for ip_range in rule.get("IpRanges", []):
                cidr = ip_range.get("CidrIp", "Unknown")
                data.append({
                    "Direction": direction,
                    "Protocol": protocol,
                    "Port Range": f"{from_port}-{to_port}",
                    "CIDR": cidr
                })
        return pd.DataFrame(data)
    
    inbound_df = create_rule_df(inbound_rules, "Inbound")
    outbound_df = create_rule_df(outbound_rules, "Outbound")
    
    return pd.concat([inbound_df, outbound_df], ignore_index=True)

def visualize_rules_streamlit(df):
    st.dataframe(df.style.applymap(lambda x: 'background-color: #ffcccb' if x == '0.0.0.0/0' else ''))

def visualize_rules_aggrid(df):
    gb = GridOptionsBuilder.from_dataframe(df)
    gb.configure_pagination()
    gb.configure_side_bar()
    gb.configure_default_column(groupable=True, value=True, enableRowGroup=True, aggFunc="sum", editable=True)
    gridOptions = gb.build()
    AgGrid(df, gridOptions=gridOptions, enable_enterprise_modules=True)

def visualize_rules_custom_html(df):
    html = """
    <style>
    .rules-table {
        border-collapse: collapse;
        width: 100%;
        font-family: Arial, sans-serif;
    }
    .rules-table th, .rules-table td {
        border: 1px solid #ddd;
        padding: 8px;
        text-align: left;
    }
    .rules-table tr:nth-child(even) {background-color: #f2f2f2;}
    .rules-table th {
        padding-top: 12px;
        padding-bottom: 12px;
        background-color: #4CAF50;
        color: white;
    }
    .inbound {color: #1e90ff;}
    .outbound {color: #32cd32;}
    .all-traffic {background-color: #ffcccb;}
    </style>
    <table class="rules-table">
        <tr>
            <th>Direction</th>
            <th>Protocol</th>
            <th>Port Range</th>
            <th>CIDR</th>
        </tr>
    """
    for _, row in df.iterrows():
        direction_class = "inbound" if row['Direction'] == "Inbound" else "outbound"
        cidr_class = "all-traffic" if row['CIDR'] == "0.0.0.0/0" else ""
        html += f"""
        <tr>
            <td class="{direction_class}">{row['Direction']}</td>
            <td>{row['Protocol']}</td>
            <td>{row['Port Range']}</td>
            <td class="{cidr_class}">{row['CIDR']}</td>
        </tr>
        """
    html += "</table>"
    st.markdown(html, unsafe_allow_html=True)

def create_hierarchical_layout(sg_config):
    G = nx.Graph()
    sg_name = sg_config.get('GroupName', 'Security Group')
    G.add_node(sg_name, node_type='security_group')
    
    for direction, rules in [('Inbound', sg_config.get('IpPermissions', [])),
                             ('Outbound', sg_config.get('IpPermissionsEgress', []))]:
        G.add_node(direction, node_type='direction')
        G.add_edge(sg_name, direction)
        for i, rule in enumerate(rules):
            rule_node = f"{direction}_rule_{i}"
            G.add_node(rule_node, node_type='rule')
            G.add_edge(direction, rule_node)
            for ip_range in rule.get('IpRanges', []):
                cidr = ip_range.get('CidrIp', 'Unknown')
                G.add_node(cidr, node_type='cidr')
                G.add_edge(rule_node, cidr)
    
    pos = nx.spring_layout(G, k=0.5, iterations=50)
    edge_x, edge_y = [], []
    for edge in G.edges():
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])

    edge_trace = go.Scatter(x=edge_x, y=edge_y, line=dict(width=0.5, color='#888'), hoverinfo='none', mode='lines')

    node_x, node_y = [], []
    for node in G.nodes():
        x, y = pos[node]
        node_x.append(x)
        node_y.append(y)

    node_trace = go.Scatter(
        x=node_x, y=node_y, mode='markers', hoverinfo='text',
        marker=dict(showscale=True, colorscale='YlGnBu', size=10, colorbar=dict(thickness=15, title='Node Type'))
    )

    node_types = [G.nodes[node]['node_type'] for node in G.nodes()]
    node_colors = [['security_group', 'direction', 'rule', 'cidr'].index(node_type) for node_type in node_types]
    node_trace.marker.color = node_colors
    node_trace.text = list(G.nodes())

    fig = go.Figure(data=[edge_trace, node_trace],
             layout=go.Layout(
                title='Security Group Hierarchical Layout',
                titlefont_size=16,
                showlegend=False,
                hovermode='closest',
                margin=dict(b=20,l=5,r=5,t=40),
                annotations=[dict(text="", showarrow=False, xref="paper", yref="paper")],
                xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                yaxis=dict(showgrid=False, zeroline=False, showticklabels=False)
             ))
    
    return fig

def create_sankey_diagram(sg_config):
    inbound_rules = sg_config.get("IpPermissions", [])
    outbound_rules = sg_config.get("IpPermissionsEgress", [])
    
    source = []
    target = []
    value = []
    label = ["Security Group"]
    
    for direction, rules in [("Inbound", inbound_rules), ("Outbound", outbound_rules)]:
        label.append(direction)
        source.append(0)
        target.append(len(label) - 1)
        value.append(len(rules))
        
        for rule in rules:
            protocol = rule.get("IpProtocol", "All")
            port_range = f"{rule.get('FromPort', 'Any')}-{rule.get('ToPort', 'Any')}"
            for ip_range in rule.get("IpRanges", []):
                cidr = ip_range.get("CidrIp", "Unknown")
                label.append(f"{protocol} {port_range} {cidr}")
                source.append(len(label) - 2)
                target.append(len(label) - 1)
                value.append(1)
    
    fig = go.Figure(data=[go.Sankey(
        node = dict(
          pad = 15,
          thickness = 20,
          line = dict(color = "black", width = 0.5),
          label = label,
          color = "blue"
        ),
        link = dict(
          source = source,
          target = target,
          value = value
      ))])

    fig.update_layout(title_text="Security Group Traffic Flow", font_size=10)
    return fig

def create_heatmap(sg_config):
    inbound_rules = sg_config.get("IpPermissions", [])
    outbound_rules = sg_config.get("IpPermissionsEgress", [])
    
    all_cidrs = set()
    all_ports = set()
    
    for rule in inbound_rules + outbound_rules:
        from_port = rule.get("FromPort", 0)
        to_port = rule.get("ToPort", 65535)
        all_ports.update(range(from_port, to_port + 1))
        for ip_range in rule.get("IpRanges", []):
            all_cidrs.add(ip_range.get("CidrIp", "Unknown"))
    
    all_cidrs = list(all_cidrs)
    all_ports = sorted(list(all_ports))
    
    heatmap_data = [[0 for _ in range(len(all_ports))] for _ in range(len(all_cidrs))]
    
    for rule in inbound_rules + outbound_rules:
        from_port = rule.get("FromPort", 0)
        to_port = rule.get("ToPort", 65535)
        for ip_range in rule.get("IpRanges", []):
            cidr = ip_range.get("CidrIp", "Unknown")
            cidr_index = all_cidrs.index(cidr)
            for port in range(from_port, to_port + 1):
                if port in all_ports:
                    port_index = all_ports.index(port)
                    heatmap_data[cidr_index][port_index] = 1
    
    fig = go.Figure(data=go.Heatmap(
        z=heatmap_data,
        x=all_ports,
        y=all_cidrs,
        colorscale='Viridis'))

    fig.update_layout(
        title='Security Group Rules Heatmap',
        xaxis_title='Ports',
        yaxis_title='CIDR Blocks')
    
    return fig

def create_chord_diagram(sg_config):
    inbound_rules = sg_config.get("IpPermissions", [])
    outbound_rules = sg_config.get("IpPermissionsEgress", [])
    
    all_cidrs = set()
    all_protocols = set()
    
    for rule in inbound_rules + outbound_rules:
        protocol = rule.get("IpProtocol", "All")
        all_protocols.add(protocol)
        for ip_range in rule.get("IpRanges", []):
            all_cidrs.add(ip_range.get("CidrIp", "Unknown"))
    
    all_cidrs = list(all_cidrs)
    all_protocols = list(all_protocols)
    
    matrix = [[0 for _ in range(len(all_protocols))] for _ in range(len(all_cidrs))]
    
    for rule in inbound_rules + outbound_rules:
        protocol = rule.get("IpProtocol", "All")
        protocol_index = all_protocols.index(protocol)
        for ip_range in rule.get("IpRanges", []):
            cidr = ip_range.get("CidrIp", "Unknown")
            cidr_index = all_cidrs.index(cidr)
            matrix[cidr_index][protocol_index] = 1
    
    fig = go.Figure(data=[go.Chord(
        matrix=matrix,
        labels=all_cidrs + all_protocols,
        colorscale='Viridis'
    )])

    fig.update_layout(title='Security Group Connections', font_size=10)
    return fig

def create_icon_based_visualization(sg_config):
    inbound_rules = sg_config.get("IpPermissions", [])
    outbound_rules = sg_config.get("IpPermissionsEgress", [])
    
    def create_rule_text(rule, direction):
        protocol = rule.get("IpProtocol", "All")
        from_port = rule.get("FromPort", "Any")
        to_port = rule.get("ToPort", "Any")
        cidrs = [ip_range.get("CidrIp", "Unknown") for ip_range in rule.get("IpRanges", [])]
        icon = "🔒" if direction == "Inbound" else "🔓"
        return f"{icon} {direction}: {protocol} {from_port}-{to_port} from {', '.join(cidrs)}"
    
    inbound_texts = [create_rule_text(rule, "Inbound") for rule in inbound_rules]
    outbound_texts = [create_rule_text(rule, "Outbound") for rule in outbound_rules]
    
    all_rules = inbound_texts + outbound_texts
    
    html = """
    <style>
    .icon-rule {
        padding: 5px;
        margin: 5px 0;
        border-radius: 5px;
        background-color: #f0f0f0;
    }
    </style>
    """
    
    for rule in all_rules:
        html += f'<div class="icon-rule">{rule}</div>'
    
    return html

def main():
    st.set_page_config(layout="wide", page_title="Security Group Analyzer")

    st.title("🛡️ AWS Security Group Analyzer")

    uploaded_file = st.file_uploader("Choose a security group configuration file", type=["json"])
    
    if uploaded_file is not None:
        try:
            file_contents = uploaded_file.getvalue().decode("utf-8")
            sg_configs = parse_security_groups(file_contents)
            
            if sg_configs:
                for i, sg_config in enumerate(sg_configs):
                    st.markdown(f"## Security Group: {sg_config.get('GroupName', 'Unnamed')}")
                    
                    # Rules Visualization
                    st.markdown("### Rules Visualization")
                    rules_df = create_enhanced_dataframe(sg_config)
                    rules_tabs = st.tabs(["Streamlit Table", "AgGrid Table", "Custom HTML Table"])
                    with rules_tabs[0]:
                        visualize_rules_streamlit(rules_df)
                    with rules_tabs[1]:
                        visualize_rules_aggrid(rules_df)
                    with rules_tabs[2]:
                        visualize_rules_custom_html(rules_df)

                    # Network Diagram Alternatives
                    st.markdown("### Network Diagram Alternatives")
                    diagram_tabs = st.tabs(["Hierarchical Layout", "Sankey Diagram", "Heatmap", "Chord Diagram", "Icon-based Visualization"])
                    with diagram_tabs[0]:
                        st.plotly_chart(create_hierarchical_layout(sg_config), use_container_width=True)
                    with diagram_tabs[1]:
                        st.plotly_chart(create_sankey_diagram(sg_config), use_container_width=True)
                    with diagram_tabs[2]:
                        st.plotly_chart(create_heatmap(sg_config), use_container_width=True)
                    with diagram_tabs[3]:
                        st.plotly_chart(create_chord_diagram(sg_config), use_container_width=True)
                    with diagram_tabs[4]:
                        st.markdown(create_icon_based_visualization(sg_config), unsafe_allow_html=True)

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
            st.error(f"An error occurred while processing the file: {str(e)}")

    st.sidebar.title("About")
    st.sidebar.info(
        "This app analyzes AWS Security Group configurations for potential security issues. "
        "It checks for overly permissive rules, large port ranges, rule duplication, "
        "and use of the default security group."
    )

if __name__ == "__main__":
    main()