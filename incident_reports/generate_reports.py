# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.


from secgym.qagen.alert_graph import AlertGraph
import os
from secgym.myconfig import CONFIG_LIST
from autogen import LLMConfig, OpenAIWrapper
import networkx as nx

def filter_config_list(config_list, model_name):
    config_list = LLMConfig(*config_list).where(tags=[model_name]).config_list
    if len(config_list) == 0:
        raise ValueError(f"model {model_name} not found in the config list, please put 'tags': ['{model_name}'] in the config list to inicate this model")
    return config_list

def generate_incident_report(nxgraph):
    """
    Generate a comprehensive incident report based on the alert graph using Azure o3-mini model.
    
    The report includes:
    - A chronological narrative of the incident
    - Analysis of each alert/event
    - Entities affected and the impact
    - Attack techniques identified
    
    Returns:
        str: The generated incident report as a formatted string
    """
    # Get a detailed string representation of the graph
    graph_representation = get_graph_representation(nxgraph)
    
    # Use o3-mini model from Azure configuration
    agent_config_list = filter_config_list(CONFIG_LIST, "o4-mini")
    llm_client = OpenAIWrapper(config_list=agent_config_list, cache_seed=None)
    
    # Create a comprehensive prompt for the LLM
    prompt = f"""
    As a cybersecurity incident analyst, analyze the following knowledge graph representing a security incident 
    and create a comprehensive incident report.
    
    Your report must include:
    1. Title of the multi-stage attack
    2. EXECUTIVE SUMMARY: Brief overview of the incident
    3. INCIDENT TIMELINE: Detailed chronological sequence of events
    4. TECHNICAL ANALYSIS: In-depth explanation of each alert/event and their relationships
    5. AFFECTED ENTITIES: All systems, users, and resources impacted
    6. ATTACK METHODOLOGY: Techniques, tactics, and procedures used
    7. INDICATORS OF COMPROMISE: Key indicators identified
    8. SEVERITY ASSESSMENT: Overall impact evaluation
    9. Important labels and keywords specific to the incident
    
    Knowledge Graph Details:
    {graph_representation}
    
    Format your analysis as a detailed technical incident report for security professionals.
    """
    
    # Generate the incident report using o3-mini
    response = llm_client.create(messages=[
        {"role": "system", "content": "You are an expert cybersecurity incident response analyst specializing in attack graph analysis."},
        {"role": "user", "content": prompt}
    ])
    
    return response.choices[0].message.content

def get_graph_representation(nxgraph):
    """
    Create a detailed string representation of the graph with all nodes and edges.
    The representation includes node properties, edge relationships, and potential attack paths.
    
    Returns:
        str: Comprehensive string representation of the graph
    """
    graph = nxgraph
    representation = []
    
    # Graph overview
    representation.append("## GRAPH OVERVIEW")
    representation.append(f"Total Nodes: {graph.number_of_nodes()}")
    representation.append(f"Total Edges: {graph.number_of_edges()}")
    representation.append(f"Is Directed: {nx.is_directed(graph)}")
    
    # Detailed node information
    representation.append("\n## NODE DETAILS")
    for node, node_data in graph.nodes(data=True):
        representation.append(f"\nNode ID: {node}")
        for key, value in node_data.items():
            representation.append(f"  {key}: {value}")
    
    # Detailed edge information
    representation.append("\n## EDGE DETAILS")
    for source, target, edge_data in graph.edges(data=True):
        representation.append(f"\nEdge: {source} → {target}")
        for key, value in edge_data.items():
            representation.append(f"  {key}: {value}")
    
    # # Identify potential attack paths if the graph is directed
    # if nx.is_directed(graph):
    #     representation.append("\n## POTENTIAL ATTACK PATHS")
    #     try:
    #         # Find nodes with no incoming edges (potential entry points)
    #         entry_points = [n for n, d in graph.in_degree() if d == 0]
            
    #         # Find nodes with no outgoing edges (potential targets)
    #         targets = [n for n, d in graph.out_degree() if d == 0]
            
    #         if entry_points and targets:
    #             for source in entry_points[:3]:  # Limit to first 3 sources for clarity
    #                 for target in targets[:3]:  # Limit to first 3 targets for clarity
    #                     try:
    #                         # Find all simple paths between entry points and targets
    #                         paths = list(nx.all_simple_paths(graph, source, target, cutoff=10))
    #                         if paths:
    #                             representation.append(f"\nPath from {source} to {target}:")
    #                             for i, path in enumerate(paths[:3]):  # Show up to 3 paths
    #                                 path_str = " → ".join(str(p) for p in path)
    #                                 representation.append(f"  Path {i+1}: {path_str}")
    #                     except (nx.NetworkXError, nx.NodeNotFound):
    #                         pass
    #     except Exception as e:
    #         representation.append(f"Could not analyze attack paths: {str(e)}")
    
    return "\n".join(representation)

def generate_reports():
    """
    Generate incident reports based on the data in the database.
    """
    # iterate over incident graphs in the database

    for filename in os.listdir("../qagen/graph_files"):
        if filename.endswith(".graphml"):
            alert_graph = AlertGraph()
            alert_graph.load_graph_from_graphml(filepath=f"../qagen/graph_files/{filename}")
            print(filename, len(alert_graph.graph.nodes))
            nx_graph = alert_graph.graph

            # Generate the incident report for the current graph using o3 
            incident_report = generate_incident_report(nx_graph)

            print(incident_report)
            

            # Save the incident report to a file
            report_filename = filename.replace(".graphml", "_incident_report.txt")
            with open(os.path.join("./", report_filename), "w") as report_file:
                report_file.write(incident_report)
                    
            # Optionally, you can also visualize the graph using the plot_custom_graph method
            # Uncomment the following line to plot the graph
            #alert_graph.plot_custom_graph()


if __name__ == "__main__":
    generate_reports()