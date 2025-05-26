import networkx as nx
import matplotlib.pyplot as plt
import pandas as pd
from secgym.utils.utils import process_entity_identifiers
from typing import List, Union
import json
import random
from collections import defaultdict
import numpy as np

class AlertGraph:
    def __init__(self) -> None:
        """
        Initialize the AlertGraph with a DataFrame of alerts.
        
        :param alerts: DataFrame containing alert entries.
        """
        self.graph = nx.Graph()
        self.next_node_id = 0
        self.entity_node_map = {}  # To map (identifier_field, value) to node_id
        self.alert_node_ids = set()
        self.incident = None
        self.alerts = []


    def build_graph_from_incident_alert(self, incident: pd.Series, alerts: Union[list[pd.Series], pd.DataFrame]) -> None:
        """Builds the graph from the DataFrame of alerts and their entities."""

        self.alerts = alerts
        if isinstance(alerts, pd.DataFrame):
            self.alerts = alerts.iterrows()
        self.incident = incident

        # time stamp to string
        self.incident['TimeGenerated'] = str(self.incident['TimeGenerated'])
        self.graph.graph['incident'] = json.dumps(self.incident.to_dict())

        for idx, alert in enumerate(self.alerts):
            alert_node_id = self.next_node_id
            self.next_node_id += 1
            self.alert_node_ids.add(alert_node_id)

            alert['TimeGenerated'] = str(alert['TimeGenerated'])
            # Add alert node
            self.graph.add_node(
                alert_node_id,
                type="alert",
                name=alert["AlertName"],
                description=alert["Description"],
                entry=json.dumps(alert.to_dict())
            )

            # Process and add entities
            entities = process_entity_identifiers(alert["Entities"])
            self._add_entities_to_graph(entities, alert_node_id)

        # check number of distinct subgraphs
        if nx.number_connected_components(self.graph) > 1:
            print(f"Number of distinct subgraphs: {nx.number_connected_components(self.graph)}")
            print("> Prune the graph to keep only the largest connected component.")
            # get the largest connected component
            largest_cc = max(nx.connected_components(self.graph), key=len)
            self.graph = self.graph.subgraph(largest_cc).copy()

    def load_graph_from_graphml(self, filepath: str) -> None:

        self.graph = nx.read_graphml(filepath, node_type=int)
        self.next_node_id = max(self.graph.nodes) + 1

        # Rebuild the entity_node_map
        # incident and alert entries back to pandas
        incident = json.loads(self.graph.graph['incident'])
        self.incident = pd.Series(incident)

        self.entity_node_map = {}
        for node, data in self.graph.nodes(data=True):
            if data.get('type') == 'entity':
                identifier_field = data.get('identifier_fields', '')
                value = data.get('value', '')
                self.entity_node_map[(identifier_field, value)] = node
            
            elif data.get('type') == 'alert':
                self.alert_node_ids.add(node)
                # alert entry back to pandas
                self.alerts.append(pd.Series(json.loads(data['entry'])))
        

    def _add_entities_to_graph(self, entities: list, alert_node_id: int) -> None:
        """Adds entities to the graph and connects them to the corresponding alert."""
        for entity in entities:
            node_type, identifier_field, value, extra_info = entity
            entity_key = (identifier_field, value)

            # Check if entity is already added to the graph
            if entity_key not in self.entity_node_map:
                entity_node_id = self.next_node_id
                self.next_node_id += 1

                # Add entity node
                self.graph.add_node(
                    entity_node_id,
                    type="entity",
                    node_type=node_type,
                    identifier_fields=identifier_field,
                    value=value
                )

                # Map entity to its node ID
                self.entity_node_map[entity_key] = entity_node_id
            else:
                # Retrieve existing node ID
                entity_node_id = self.entity_node_map[entity_key]

            # Connect the alert to the entity
            #TODO: Add edge attributes for extra_info, use gpt to generate the relationship
            self.graph.add_edge(alert_node_id, entity_node_id)

    def save_to_graphml(self, filepath: str) -> None:
        """
        Saves the graph to a GraphML file.
        
        :param filepath: The path where the GraphML file will be saved.
        """
        nx.write_graphml(self.graph, filepath)
        print(f"Graph saved to {filepath}")

    def _prepare_node_to_plot(self, graph, base_node_size=15000, max_line_length=80):
        # Define node sizes and colors based on type
        node_sizes = []
        node_colors = []
        labels = {}

        for node, data in graph.nodes(data=True):
            if data.get('type') == 'alert':
                # Show just the alert name
                label = f"ID: {node}\n{data.get('name', '')}"
                
                # Uncomment the following lines to include the description
                # full_description = data.get('description', '')
                # wrapped_description = "\n".join(textwrap.wrap(full_description, max_line_length))
                # label = f"ID: {node}\n{data.get('name', '')}\n{wrapped_description}"
                
                labels[node] = label[:max_line_length+7]
                node_sizes.append(base_node_size)  # Size for type alert
                node_colors.append('#ADD8E6')  # Light blue color for type alert
            elif data.get('type') == 'entity':
                # Concatenate identifier_field and value for entities
                identifier_field = data.get('identifier_fields', '')
                value = data.get('value', '')
                label = f"ID: {node}\n{identifier_field}: {value}"
                labels[node] = label[:max_line_length+7]
                node_sizes.append(base_node_size // 3)  # Smaller size for type entity
                node_colors.append('#FFB6C1')  # Light pink color for type entity
        
        return node_sizes, node_colors, labels
    
    def plot_question_graph(self, question, figsize=(22, 16), show_plot=True, save_figure=False, file_path=None):
        """
        Plots a subgraph containing start entities, shortest alert path, and end entities based on the `question` dict.
        
        Parameters:
        - question (dict): Contains the fields:
            - start_alert: int
            - end_alert: int
            - start_entities: list[int]
            - end_entities: list[int]
            - shortest_alert_path: list[int]
        - figsize (tuple): Size of the plot.
        - show_plot (bool): Whether to display the plot.
        - save_figure (bool): Whether to save the plot as an image.
        - file_path (str): File path to save the plot.
        """
        # Extract nodes from the question dictionary
        start_entities = question.get('start_entities', [])
        shortest_alert_path = question.get('shortest_alert_path', [])
        end_entities = question.get('end_entities', [])

        # Combine all nodes to include in the subgraph
        included_nodes = set(start_entities + shortest_alert_path + end_entities)

        # Create the subgraph
        subgraph = self.graph.subgraph(included_nodes)

        # Prepare node sizes, colors, and labels using the helper function
        node_sizes, node_colors, labels = self._prepare_node_to_plot(subgraph)

        # Use a simple layout since the graph is chain-like
        pos = nx.spring_layout(subgraph, seed=42)  # Spring layout ensures chain-like visualization

        # Set up the figure size
        plt.figure(figsize=figsize)

        # Draw the subgraph
        nx.draw(subgraph, with_labels=True, labels=labels, node_size=node_sizes, node_color=node_colors, font_size=10)

        # Save the plot if required
        if save_figure and file_path:
            plt.savefig(file_path, dpi=600)
        
        # Show the plot if required
        if show_plot:
            plt.show()
        else:
            plt.close()

    def plot_custom_graph(self, 
                        root=0, 
                        figsize=(22, 16),
                        base_node_size=15000, 
                        max_line_length=80, 
                        show_plot=True, 
                        save_figure=False, 
                        file_path=None,
                        layout='spring'
                        ):
        
        # Prepare the node sizes, colors, and labels
        node_sizes, node_colors, labels = self._prepare_node_to_plot(self.graph, base_node_size, max_line_length)

        # Define the custom tree layout
        if layout == 'tree':
            pos = self.hierarchy_pos(root)
        elif layout == 'circular':
            pos = nx.circular_layout(self.graph)
        elif layout == 'spring':
            pos = nx.spring_layout(self.graph)
        elif layout == 'fruchterman_reingold':
            pos = nx.fruchterman_reingold_layout(self.graph)
        elif layout == 'spectral':
            pos = nx.spectral_layout(self.graph)
        elif layout == 'shell':
            pos = nx.shell_layout(self.graph)
        elif layout == 'random':
            pos = nx.random_layout(self.graph)
        elif not isinstance(layout, str):
            pos = layout
        else:
            raise ValueError("Invalid layout. Choose 'tree' or 'circular'.")
        
        # Set up the figure size
        plt.figure(figsize=figsize)
        
        # Draw the graph
        nx.draw(self.graph, pos=pos, with_labels=True, labels=labels, node_size=node_sizes, node_color=node_colors, font_size=10)

        # Save the plot if required
        if save_figure and file_path is not None:
            plt.savefig(file_path, dpi=600)
        
        # Show the plot if required
        if show_plot:
            plt.show()
        else:
            plt.close()
    
    def get_e2e_paths(self):
        """
        Get all paths from one entity to another entity.

        1. start node is an entity node
        2. end node is an entity node
        3. path includes alert and entity nodes
        
        - undirect: reverse the whole path is another path
        - should not include entity node to self
        - should be the shortest path, only get one path from each start node to end node
        """
        e2e_paths = []
        # iterate all entity nodes
        for entity_node in self.entity_node_map.values():
            # get all paths from entity node to entity node
            for entity_node2 in self.entity_node_map.values():
                if entity_node == entity_node2:
                    continue
                paths = nx.all_shortest_paths(self.graph, source=entity_node, target=entity_node2)
                # get the first path
                e2e_paths.append(next(paths))
        
        print(f"Total end-to-end paths: {len(e2e_paths)}")
        # print number base on len of the list
        length_count = {}
        for path in e2e_paths:
            length = len(path)
            if length not in length_count:
                length_count[length] = 1
            else:
                length_count[length] += 1
        
        for length, count in length_count.items():
            print(f"Length {length}: {count}")
         
        return e2e_paths

    def get_graph_patterns(self):
        """
        For each alert node, print 
        1. num of entities it connected
        2. num of leaf entities it connected
        """
        print("Graph patterns:")

        for alert_node in self.alert_node_ids:
            entities = [node for node in self.graph.neighbors(alert_node) if self.graph.nodes[node]['type'] == 'entity']
            leaf_entities = [node for node in entities if self.graph.degree(node) == 1]
            print(f"Alert node {alert_node}: {len(entities)} entities, {len(leaf_entities)} leaf entities")
    

    def get_complet_alert_paths(self, alert_paths_dict) -> list:
        return [alert_paths_dict['start_entities']] + alert_paths_dict['shortest_alert_path'] + [alert_paths_dict['end_entities']]

    def get_alert_paths(self, num_select=-1, k=10, verbose=True):
        """
        Question from any two alerts:
		- Pick any two alert (can be same)
		- Select k entities from on alert that is farthest from another entity (if same alert, the entity should not be the same)

        Args:
        - num_select: number of alert paths to select, if -1, select all
        - k: number of entities to be selected from the farthest entities
        - verbose: print out the alert pairs and selected entities

        Return:
        - list of alert paths, each path is a dict with keys: start_alert, end_alert, start_entities, end_entity, shortest_alert_path
        """
        if num_select == 0:
            return []

        def get_farthest_entities(start_alert, end_alert):
            start_entities = [node for node in self.graph.neighbors(start_alert) if self.graph.nodes[node]['type'] == 'entity']
            # print(f"Start entities: {start_entities}")
            dist_map = {}
            for entity in start_entities:
                tmp_dist = nx.shortest_path_length(self.graph, source=entity, target=end_alert)
                if tmp_dist not in dist_map:
                    dist_map[tmp_dist] = [entity]
                else:
                    dist_map[tmp_dist].append(entity)
            
            # print(f"Dist map: {dist_map}")
            #TODO: Customized the selection of entities from furthest to different lengths
            max_dist = max(dist_map.keys())
            return dist_map[max_dist]
    
        # construct alert pairs
        alert_nodes = list(self.alert_node_ids)
        alert_pairs = [(alert1, alert2) for alert1 in alert_nodes for alert2 in alert_nodes]

        alert_paths = []
        for alert1, alert2 in alert_pairs:
            # get entities connected to alert1 that is farthest from alert2 node
            # print(f"Alert pair: {alert1} -> {alert2}")

            farthest_start_entities = get_farthest_entities(alert1, alert2)
            if alert1 != alert2: # if start and end alert is different
                if k > len(farthest_start_entities):
                    selected_from_a1 = farthest_start_entities
                    # print(f"Warning: Construct path from alert {alert1} to alert {alert2}, expect {k} entities to be as inital context, but only {len(farthest_start_entities)} entities available.")
                else:
                    selected_from_a1 = random.sample(farthest_start_entities, k)

                # get entities connected to alert2 that is farthest from alert1 node
                farthest_end_entities = get_farthest_entities(alert2, alert1)

                # filter out node_type  -> host and process  and try select first, if none don't filter
                filtered_end_entities = [entity for entity in farthest_end_entities if self.graph.nodes[entity]['node_type'] not in ['host', 'process']]
                if len(filtered_end_entities) > 0:
                    selected_from_a2 = random.sample(filtered_end_entities, 1)
                else:
                    if verbose:
                        print(f"Warning: No entity with node_type host or process connected to alert {alert2}, select from all entities.")
                    selected_from_a2 = random.sample(farthest_end_entities, 1)
            else: # start and end alert is the same
                if len(farthest_start_entities) - 1 <= 0:
                    if verbose:
                        print(f"Alert {alert1} has only one entity connected, skip.")
                    continue
                # if k >= len(farthest_start_entities):
                #     print(f"Warning: Construct path using the same alert, expect {k} entities to be as inital context, but only {len(farthest_start_entities)} entities available in alert id {alert1}.")
                #     print(f'Warning: Use {len(farthest_start_entities) - 1} entities instead.')
                selected_from_a1 = random.sample(farthest_start_entities, min(k, len(farthest_start_entities)-1))
                
                # sample 1 from the rest of farthest_start_entities, start and end entity should not be the same
                remaining_entities = [entity for entity in farthest_start_entities if entity not in selected_from_a1]
                selected_from_a2 = random.sample(remaining_entities, 1)
            
            # get all shortest path between alert1 and alert2  and random select one
            shortest_alert_paths = list(nx.all_shortest_paths(self.graph, source=alert1, target=alert2))
            shortest_alert_path = random.choice(shortest_alert_paths)

            # if selected_from_a2 in selected_from_a1, remove it
            for entity in selected_from_a1:
                val_a1 = self.graph.nodes[entity]['value']
                val_a2 = self.graph.nodes[selected_from_a2[0]]['value']
                if val_a1 in val_a2 or val_a2 in val_a1:
                    if verbose:
                        print(f"Warning: Remove the same entity from start and end entities.")
                    selected_from_a1.remove(entity)
                    break
            if len(selected_from_a1) == 0:
                if verbose:
                    print(f"Warning: No entity selected from alert {alert1}, skip.")
                continue
            # if selected_from_a2[0]['value'] in selected_from_a1:
            #     selected_from_a1.remove(selected_from_a2[0])
            #     print(f"Warning: Remove the same entity from start and end entities.")

            alert_paths.append(
                {
                    "start_alert": alert1,
                    "end_alert": alert2,
                    "start_entities": selected_from_a1,
                    "end_entities": selected_from_a2,
                    "shortest_alert_path": shortest_alert_path
                }
            )
            if verbose:
                print(f"Alert pair: {alert1} -> {alert2}, start entities: {selected_from_a1}, end entity: {selected_from_a2}, shortest alert path: {shortest_alert_path}")
                print(f"-"*100)
        
        if num_select > 0 and num_select < len(alert_paths):
            alert_paths = self.select_alert_paths(alert_paths, num_select)

        print(f"Total alert paths: {len(alert_paths)}. Expected: alert_num ^ 2 = {len(alert_nodes) ** 2}, Selected: {len(alert_paths)}")
        return alert_paths

    @staticmethod
    def select_alert_paths(alert_paths, m):
        """
        Select m paths based on the difficulty ratio of "shortest_alert_path".

        Args:
            alert_paths (list[dict]): List of dictionaries containing alert paths.
            m (int): Number of paths to select.

        Returns:
            list[dict]: List of selected alert paths.
        """
        if m >= len(alert_paths):
            return alert_paths 
        # Group paths by difficulty
        difficulty_groups = defaultdict(list)
        for path in alert_paths:
            difficulty = len(path["shortest_alert_path"])
            difficulty_groups[difficulty].append(path)
        
        # Sort difficulties in ascending order
        difficulties = sorted(difficulty_groups.keys())
        counts = [len(difficulty_groups[d]) for d in difficulties]
        
        # Calculate ratios
        total_count = sum(counts)
        ratios = [count / total_count for count in counts]

        # Normalize ratios
        smoothed = np.power(ratios, 0.5)
        ratios = smoothed / sum(smoothed)  # Renormalize to sum to 1
        
        # Allocate but cap at the number of paths available for each difficulty
        # allocated_counts = [int(r * m) for r in ratios]
        allocated_counts = [min(int(r * m), len(difficulty_groups[d])) for r, d in zip(ratios, difficulties)]

        # print(f"Difficulty : Ratios")
        # for i, difficulty in enumerate(difficulties):
        #     print(f"{difficulty} : {ratios[i]}")
        # print(len(alert_paths), f"Allocated counts: {allocated_counts}", f"Leftover: {m - sum(allocated_counts)}")

        # Handle leftover counts
        leftover = m - sum(allocated_counts)
        while leftover > 0:
            for i in range(len(difficulties)-1, -1, -1):  # Favor higher difficulties
                if leftover == 0:
                    break
                if allocated_counts[i] < len(difficulty_groups[difficulties[i]]):
                    allocated_counts[i] += 1
                    leftover -= 1
        
        print(allocated_counts)
        # Randomly select paths based on allocated counts
        selected_paths = []
        for i, difficulty in enumerate(difficulties):
            selected_paths.extend(random.sample(difficulty_groups[difficulty], min(allocated_counts[i], len(difficulty_groups[difficulty]))))
        
        assert len(selected_paths) == m, f"Expected {m} paths, got {len(selected_paths)}"
        return selected_paths

    def get_node(self, node_id):
        return self.graph.nodes(data=True)[node_id]
