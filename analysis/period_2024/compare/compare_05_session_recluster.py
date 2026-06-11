"""
Compare step 05 (2024 vs 2021/2022): Re-cluster sessions via TF-IDF + KMeans.

Vectorizes each session's command sequence with TF-IDF, sweeps the number of
KMeans clusters using the silhouette score to pick the best k, then prints the
attacker IPs grouped by cluster, for both periods.

Input  : <period>/data/5-session归类.json for both periods.
Output : printed cluster assignments (no file written)

NOTE: marked in the original as "effect not good" (poor clustering quality).
"""
# --coding:utf-8--
# effect not good
import os
import json
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import KMeans
from sklearn.metrics import silhouette_score
import ast

# === Config ===
# Original (hardcoded) 2021 root: "D:/科研/Honey-GPT/Honeypot Data/Data-process-new"
# Original (hardcoded) 2024 root: "../../"
ROOT_2024 = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROOT_2021 = os.path.join(os.path.dirname(ROOT_2024), "period_2021_2022")

def get_sorted_comd_type_dict(path):
    with open(path + '/data/5-session归类.json', 'r') as file:
        sample_dict = json.load(file)
    return sample_dict


def change_dict(original_dict):
    # New dict to store the converted data
    new_dict = {}

    # Iterate over the original dict
    for key_tuple, inner_dict in original_dict.items():
        # Extract the inner dict's keys (i.e. the IP addresses) as the new value list
        ip_list = list(inner_dict.keys())

        # Use the original dict's value (the command list) as the new dict's key
        # Note: it must be hashable, so convert it into a tuple
        new_dict[ ast.literal_eval(key_tuple)]= ip_list

    # Return the new dict to inspect the result
    return new_dict

def cluster(data):
    ips = list(data.keys())
    commands = [';'.join(seq) for seq in data.values()]

    vectorizer = TfidfVectorizer()
    X = vectorizer.fit_transform(commands)

    # Try different cluster counts to find the best one
    silhouette_scores = []
    cluster_range = range(2, len(data))  # assume each sequence comes from at least one independent attacker

    for n_clusters in cluster_range:
        kmeans = KMeans(n_clusters=n_clusters, random_state=42)
        labels = kmeans.fit_predict(X)
        score = silhouette_score(X, labels)
        silhouette_scores.append(score)
        print(f"Number of clusters: {n_clusters}, Silhouette Score: {score}")

    # Find the cluster count with the highest silhouette coefficient
    best_n_clusters = cluster_range[silhouette_scores.index(max(silhouette_scores))]
    print(f"The best number of clusters is {best_n_clusters}")

    # Run K-means clustering with the best cluster count
    kmeans = KMeans(n_clusters=best_n_clusters, random_state=42)
    kmeans.fit(X)

    # Output the best clustering result
    print("Cluster assignments:", kmeans.labels_)
    cluster_assignments = kmeans.labels_
    # Build a dict keyed by cluster label, with the corresponding IP-address list as value
    clusters = {}
    for idx, label in enumerate(cluster_assignments):
        clusters.setdefault(label, []).append(ips[idx])

    # Output the IP addresses corresponding to each cluster
    for cluster_id, cluster_ips in clusters.items():
        print(f"Cluster {cluster_id}:")
        ips = []
        for ip in cluster_ips:
            ips += data[ip]
        print(ips)

# Example data


dict_2024 = change_dict(get_sorted_comd_type_dict(ROOT_2024))
dict_2021 = change_dict(get_sorted_comd_type_dict(ROOT_2021))

cluster(dict_2024)

cluster(dict_2021)
