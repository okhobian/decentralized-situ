import matplotlib.pyplot as plt
from scipy.cluster.hierarchy import dendrogram, linkage, to_tree

def model_analysis(y_true_classes, y_pred_classes, activity_mapping):
    
    # F1 score
    f1_macro = f1_score(y_true_classes, y_pred_classes, average='macro')
    f1_micro = f1_score(y_true_classes, y_pred_classes, average='micro')
    f1_weighted = f1_score(y_true_classes, y_pred_classes, average='weighted')
    f1_scores_per_class = f1_score(y_true_classes, y_pred_classes, average=None)        # Calculate F1 scores for each class
    f1_scores_df = pd.DataFrame({'Class': ACTIVITIES, 'F1 Score': f1_scores_per_class}) # Convert to a DataFrame for better readability

    print("Macro F1 score:", f1_macro)
    print("Micro F1 score:", f1_micro)
    print("Weighted F1 score:", f1_weighted)
    print(f1_scores_df)

    ################

    # confusion matrix
    conf_matrix = confusion_matrix(y_true_classes, y_pred_classes)
    axis_labels = [activity_mapping[i] for i in range(len(activity_mapping))]   # Replace indices with string labels

    # plot the confusion matrix
    plt.figure(figsize=(10, 8))
    sns.heatmap(conf_matrix, annot=True, fmt='g', cmap='Blues', xticklabels=axis_labels, yticklabels=axis_labels)
    plt.xlabel('Predicted labels')
    plt.ylabel('True labels')
    plt.show()

def add_parent_info(node, parent=None):
    """
    Recursively add parent information to each node.
    """
    node.parent = parent
    if node.left is not None: add_parent_info(node.left, node)
    if node.right is not None: add_parent_info(node.right, node)

def find_path_to_root(node):
    """
    Find the path from the current node to the root.
    """
    path = []
    while node is not None:
        path.append(node)
        node = node.parent
    return path

def find_LCA_and_distance(nodeA, nodeB):
    """
    Find the LCA of nodeA and nodeB and calculate the sum of the distances from nodeA and nodeB to their LCA.
    """
    # build paths from nodeA and nodeB to the root
    pathA = find_path_to_root(nodeA)
    pathB = find_path_to_root(nodeB)
    
    indexA, indexB = 0, 0
    while indexA < len(pathA) and indexB < len(pathB):
        if pathA[indexA].id == pathB[indexB].id:
            break
        else:
            indexA += 1
            indexB += 1

    return indexA+indexB

def plot_dendrogram(Z):
    # Plotting dendrogram
    plt.figure(figsize=(10, 5))
    plt.title("Hierarchical Clustering Dendrogram")
    plt.xlabel("Homes")
    plt.ylabel("Distance")
    dendrogram(Z)
    plt.ylim(ymin=-0.01)
    plt.show()