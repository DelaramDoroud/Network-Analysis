import networkx as nx
import matplotlib.pyplot as plt
import random
import copy
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import seaborn as sns
import pandas as pd
import matplotlib.animation as animation

##########change threshold , gossipers , malicious to control the simulation#############
value_of_threshold = 0.06
number_of_gossipers = 2
number_of_malicious = 100
strategy = "random"  # Options: "random", "degree", "betweenness", "closeness"
#########################################################################################
######## Function to select malicious nodes based on strategy ##########
def select_malicious_nodes(strategy, num, graph):
    if strategy == "random":
        return random.sample(list(graph.nodes()), num)
    elif strategy == "degree":
        sorted_nodes = sorted(degree_dict, key=degree_dict.get, reverse=True)
    elif strategy == "betweenness":
        sorted_nodes = sorted(betweenness_dict, key=betweenness_dict.get, reverse=True)
    elif strategy == "closeness":
        sorted_nodes = sorted(closeness_dict, key=closeness_dict.get, reverse=True)
    else:
        raise ValueError("Invalid strategy")
    return sorted_nodes[:num]

random.seed(42) # set seed for reproducibility
myGraph = nx.read_edgelist("email-Eu-core.txt", create_using=nx.DiGraph())
myGraph_undirected = myGraph.to_undirected()
#cleaning dataset
myGraph_undirected.remove_edges_from(nx.selfloop_edges(myGraph_undirected))
myGraph_undirected.remove_nodes_from(list(nx.isolates(myGraph_undirected)))
largest_cc = max(nx.connected_components(myGraph_undirected), key=len)
graph_sub=(myGraph_undirected.subgraph(largest_cc))
degree_dict = dict(graph_sub.degree())
betweenness_dict = nx.betweenness_centrality(graph_sub)
closeness_dict = nx.closeness_centrality(graph_sub)
# start_node = random.choice(list(graph_sub.nodes()))
gossipers = random.sample(list(graph_sub.nodes()), number_of_gossipers) 
remaining_nodes = list(set(graph_sub.nodes()) - set(gossipers))
malicious = select_malicious_nodes(strategy, number_of_malicious, graph_sub)
# malicious = random.sample(remaining_nodes, number_of_malicious)
node_colors = []
for node in graph_sub.nodes():
    if node in gossipers:
        node_colors.append("green")
    elif node in malicious:  
        node_colors.append("red")
    else:
        node_colors.append("gray")

pos = nx.spring_layout(graph_sub, seed=42)
plt.figure(figsize=(6, 6))
nx.draw(graph_sub, pos, with_labels=False, node_color=node_colors)
plt.title("Initial graph with gossipers (green) and malicious nodes (red)")
plt.show()

original_message = "this is my secret message"
threshold = value_of_threshold
messages = {node: None for node in graph_sub.nodes()}
def tamper_message(message):
    # Randomly change a character in the message
    message = list(message)
    replacement_options = ["1111", "2222", "3333", "4444", "5555","6666","7777", "8888", "9999"]
    index = random.randint(0, len(message) - 1)
    message[index] = random.choice(replacement_options)
    return ''.join(message)
for node in gossipers:
    messages[node] = original_message
final_colors = []
color_frames=[]
message_frames = []
def get_colors(msg_dict):
    colors = []
    for node in graph_sub.nodes():
        msg = msg_dict[node]
        if msg is None:
            colors.append("gray")
        elif msg == original_message:
            colors.append("green")
        else:
            colors.append("red")
    return colors
color_frames.append(get_colors(messages))
message_frames.append(copy.deepcopy(messages))
isChanged = True
while isChanged:
    isChanged = False
    new_messages = copy.deepcopy(messages)
    for node in graph_sub.nodes():
        if messages[node] is not None:
            continue
        neighbors = list(graph_sub.neighbors(node))
        if not neighbors:
            continue
        accepted = [n for n in neighbors if messages[n] is not None]
        if len(accepted) / len(neighbors) >= threshold:
            source_msg = random.choice([messages[n] for n in accepted])
            if node in malicious:
                source_msg = tamper_message(source_msg)
            new_messages[node] = source_msg
            isChanged = True
    
    if isChanged:
        messages = new_messages
        color_frames.append(get_colors(messages))
        message_frames.append(copy.deepcopy(messages))
pos = nx.spring_layout(graph_sub, seed=42)
fig, ax = plt.subplots(figsize=(19.2, 10.8))
def update(frame):
    ax.clear()
    ax.set_title(f"Iteration {frame}")
    nx.draw(graph_sub, pos, node_color=color_frames[frame],ax=ax)
    # labels = {
    #     node: message_frames[frame][node] if message_frames[frame][node] is not None else ""
    #     for node in graph_sub.nodes()
    # }    
    # nx.draw_networkx_labels(graph_sub, pos, labels, font_size=7)
    plt.savefig(f"iteration_{frame}.png")
plt.title("Final graph: Green = Original, Red = Tampered, Gray = No message")
ani = animation.FuncAnimation(fig, update, frames=len(color_frames), interval=500, repeat=False)

plt.show()

total_nodes = len(graph_sub)
final_msgs = list(messages.values())

coverage_percent = 100 * sum(1 for msg in final_msgs if msg is not None) / total_nodes
original_percent = 100 * sum(1 for msg in final_msgs if msg == original_message) / total_nodes
steps_to_converge = len(message_frames) - 1
unique_msg_count = len(set([msg for msg in messages.values() if msg is not None]))

print(f"Coverage (%): {coverage_percent:.1f}")
print(f"Original Message (%): {original_percent:.1f}")
print(f"Steps to Convergence: {steps_to_converge}")
print(f"Unique Messages: {unique_msg_count}")

node_list=list(messages.keys())
msg_list = [messages[node] if messages[node] else "" for node in node_list]
vectorizer = TfidfVectorizer(lowercase=False, stop_words=None, norm=None)
X = vectorizer.fit_transform(msg_list)
similarity_matrix = cosine_similarity(X)
df = pd.DataFrame(similarity_matrix, index=msg_list, columns=msg_list)
plt.figure(figsize=(12, 10))
sns.heatmap(df, cmap="coolwarm", annot=False, vmin=0, vmax=1)
plt.title("Cosine Similarity of Messages Across Nodes")
plt.xticks([])
plt.yticks([])
plt.tight_layout()
plt.show()
# Compute number of nodes with information at each step
nodes_with_info = [sum(1 for msg in frame.values() if msg is not None) for frame in message_frames]
steps = list(range(len(message_frames)))
total_nodes = len(graph_sub)

# Plot diffusion over time
plt.figure(figsize=(10, 6))
plt.plot(steps, nodes_with_info, marker='o', color='blue', label='Nodes with Information')
plt.axhline(y=total_nodes, color='red', linestyle='--', label='Total Nodes')
plt.title("Information Diffusion Over Time")
plt.xlabel("Step")
plt.ylabel("Number of Nodes")
plt.legend()
plt.tight_layout()
plt.grid(True)
plt.savefig(f"diffusion_curve.png")
plt.show()

thresholds = [0.01, 0.02, 0.06, 0.08, 0.09, 0.1]
coverage = [100, 100, 100, 100, 1.9, 1.4]           
original_msg = [99.5, 99.1, 99.5, 99.1, 1.9, 1.4]  

x = np.arange(len(thresholds)) 
width = 0.35 

fig, ax = plt.subplots(figsize=(10, 6))
bars1 = ax.bar(x - width/2, coverage, width, label='Information Coverage (%)', color='#1f77b4')
bars2 = ax.bar(x + width/2, original_msg, width, label='Original Message (%)', color='#2ca02c')

ax.set_xlabel('Threshold Value')
ax.set_ylabel('Percentage')
ax.set_title('Effect of Threshold on Information Spread')
ax.set_xticks(x)
ax.set_xticklabels([str(t) for t in thresholds])
ax.legend()

plt.tight_layout()
plt.show()
