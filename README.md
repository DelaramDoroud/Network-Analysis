# 📊 Network Analysis Assignments

This repository contains three assignments completed for the **Network Analysis** course (Academic Year 2024/2025).  
The projects focus on analyzing the **Email-Eu-core** dataset and studying important aspects of complex networks, including **community detection**, **social contagion**, and **robustness**.

---

## 📝 Assignment Summaries

### **Assignment 1 – Community Detection**
- **Dataset**: Email-Eu-core network  
- **Goal**: Detect and analyze communities using **Louvain** and **Leiden** algorithms.  
- **Highlights**:
  - Compared modularity, execution time, and structure of detected communities.  
  - Achieved strong agreement between methods using **NMI** (0.79) and **ARI** (0.69).  
  - Visualized community structures to confirm clustering patterns.  

---

### **Assignment 2 – Social Contagion with Malicious Nodes**
- **Dataset**: Email-Eu-core network  
- **Goal**: Simulate the spread of a secret message in the presence of **gossipers** and **malicious nodes**.  
- **Highlights**:
  - Implemented a **threshold model** for message adoption.  
  - Analyzed how malicious nodes corrupt information and reduce integrity.  
  - Compared targeting strategies (random, degree, betweenness, closeness).  
  - Evaluated message similarity using **cosine similarity heatmaps**.  

---

### **Assignment 3 – Network Robustness**
- **Dataset**: Synthetic BA model + Email-Eu-core network  
- **Goal**: Study how different **attack strategies** (random, degree, betweenness, closeness, PageRank) affect network connectivity.  
- **Highlights**:
  - Measured robustness via size of the **giant component**.  
  - Compared node removal strategies, showing vulnerability to centrality-based attacks.  
  - Proposed reinforcement strategies (hubs, high-betweenness, low-degree).  
  - Found that **high-betweenness reinforcement** gives the best trade-off between robustness and edge cost.  

---

## ⚙️ Technologies & Tools
- **Python** (NetworkX, Matplotlib, NumPy, Scikit-learn)  
- **Graph Visualization** libraries  
- **Cosine Similarity** analysis for information integrity  
