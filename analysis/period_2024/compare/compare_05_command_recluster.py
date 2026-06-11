"""
Compare step 05 (2024 vs 2021/2022): Re-cluster commands via TF-IDF + KMeans.

Builds a flat list of command types/patterns for each period, vectorizes the
2024 list with TF-IDF, runs a 2-cluster KMeans, and prints the cluster labels.

Input  : <period>/data/3-大类提取.json , <period>/data/4-复杂指令类型分析-sorted.json
         for both periods.
Output : printed cluster labels (no file written)
"""
# --coding:utf-8--
import os
import json
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import KMeans
import ast

# === Config ===
# Original (hardcoded) 2021 root: "D:/科研/Honey-GPT/Honeypot Data/Data-process-new"
# Original (hardcoded) 2024 root: "../.."
ROOT_2024 = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROOT_2021 = os.path.join(os.path.dirname(ROOT_2024), "period_2021_2022")

def get_sorted_comd_type_dict(path):
    with open(path + '/data/3-大类提取.json', 'r') as file:
        sample_dict = json.load(file)
    with open(path + '/data/4-复杂指令类型分析-sorted.json', 'r') as file:
        complex_dict = json.load(file)

    comd_type_list = []

    for i in sample_dict:
        comd_type_list.append(i)

    for i in complex_dict:
        comd_type_list.append(" ".join(ast.literal_eval(i)))

    return comd_type_list


dict_2024 = get_sorted_comd_type_dict(ROOT_2024)
dict_2021 = get_sorted_comd_type_dict(ROOT_2021)

# Use the TF-IDF vectorization method
vectorizer = TfidfVectorizer()
X = vectorizer.fit_transform(dict_2024)

# Use the K-means clustering algorithm
kmeans = KMeans(n_clusters=2, random_state=0).fit(X)

# Output the clustering result
print("Cluster labels:", kmeans.labels_)
