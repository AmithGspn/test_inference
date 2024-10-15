#!/usr/bin/env python3

# Expand a DecisionTreeClassifier to a text file which contains entries to configure `MyIngress.ml_code` table.
#  The structure of an entry is described here: https://github.com/p4lang/behavioral-model/blob/main/docs/runtime_CLI.md#table_add
#
# See an example in pcaps/s1-commands.txt

import numpy as np
import pandas as pd
import argparse
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import accuracy_score
from sklearn.tree import export_graphviz
import pydotplus
import itertools
import math


parser = argparse.ArgumentParser()

# Add argument
parser.add_argument('-i', default="./pcaps/dt.model", help='path to the input model')
parser.add_argument('-o', default="./pcaps/s1-commands.txt", help='path to the output file')

args = parser.parse_args()
inputfile  = args.i
outputfile = args.o


FEATURE_NAMES = ["len", "diffLen"]

priority=0
split_ranges = {feature: [] for feature in FEATURE_NAMES}
def write_entry(f, domain, classification):
    global priority
    priority += 1
    clause = []
    # for each feature in order
    for i in range(0, len(FEATURE_NAMES)):
        fe = FEATURE_NAMES[i]
        # this feature is not involved in this path
        if fe not in domain:
            continue
        val = domain[ fe ]
        lo = val["min"]
        hi = val["max"]
        print(lo)
        print(hi)
        # we are in a Decision Tree condition (lo, hi], i.e., lo < v <= hi
        #  need to translate to [lo, hi]
        lo = int(lo) + 1
        hi = int(hi) # convert to integer
        split_ranges[FEATURE_NAMES[i]] = []
        range_start = lo

        # Loop until range_end exceeds hi value
        while range_start <= hi:
            nearest_power = 2 ** math.ceil(math.log2(range_start + 1))
            range_end = nearest_power - 1
            
            # Adjust range_end if it exceeds hi
            if range_end > hi:
                range_end = hi
                
            # mask = generate_mask(range_start, range_end)
            split_ranges[FEATURE_NAMES[i]].append((range_start, range_end))
            # print(split_ranges)
            # Update range_start for the next iteration
            range_start = range_end + 1
    # print(split_ranges)
    combinations_list = list(itertools.product(split_ranges["len"], split_ranges["diffLen"]))
    print(combinations_list)

    # Loop through split_ranges to create formatted strings and append to clause
    for combination in combinations_list:
        value_a, mask_a = combination[0]
        value_b, mask_b = combination[1]

        priority += 1
        # command = f"match {hex(value_a)}/{hex(mask_a)} {hex(value_b)}/{hex(mask_b)} action forward_ternary dstAddr 0x1 port_id 0x0"
        f.write("table_add MyIngress.ml_code set_result {}->{} {}->{} => {} {}\n".format(value_a, mask_a, value_b, mask_b, classification, priority ))

        # print(command)
        # print(combination[1])
        # clause = []
        # priority += 1
        # for value, mask in combination:
        #     clause.append("{}->{}".format(lo, hi))
        #     print(clause)
        # f.write("table_add MyIngress.ml_code set_result {} => {} {}\n".format( " ".join(clause), classification, priority ))     
        

# minimize the boolean expression which is collected along a path
def minimize( path ):
    # range of possible values of each feature 
    DOMAIN = {
        "len" : {
            "min": 0, 
            "max": 0xFFFF #max size of an IP packet
        },
        "diffLen" : {
            "min": 0, 
            "max": 2*0xFFFF #2 times of packet size
        }
    }

    domain = DOMAIN
    for (feature, sign, threshold) in path:
        if feature not in DOMAIN:
            raise Exception("need to set in DOMAIN min and max of", feature)

        val = domain[ feature ]
        
        if sign == "<=":
            # as we have condition (feature <= threshold)
            #   then we reduce its upper bound (max)
            val["max"] = threshold
        else:
            # here we have condition (feature > threshold)
            #   then we increase its lower bound (min)
            val["min"] = threshold
    return domain


# Visite the tree using Depth-first search
def visite(dt, node_id, features, file, path = [] ):
    print("visit")
    classes = dt.classes_
    tree  = dt.tree_
    left  = tree.children_left
    right = tree.children_right

    # do we reach a leaf node?
    is_leaf = (left[ node_id ] == right[ node_id ])

    if is_leaf:
        # print path from root to this leaf node
        new_path = []
        for (n_id, sign) in path:
            threshold = tree.threshold[n_id]
            feature   = features[n_id]
            new_path.append( (feature, sign, threshold) )

        clause = minimize( new_path )

        # see https://scikit-learn.org/stable/auto_examples/tree/plot_unveil_tree_structure.html#what-is-the-values-array-used-here
        a = list(tree.value[node_id][0])
        # get the class that has the max number of samples
        class_index = a.index(max(a))
        classification = classes[ class_index ]

        # wirte the node information into text file
        write_entry(f, clause, classification)
        return
    else:
        # need to clone the path to avoid being add nodes in the left branch
        org_path = path.copy()
        # visit the left branch first
        path.append( (node_id, "<=") )
        visite( dt, left[ node_id ], features, file, path )

        # visite the right branch
        org_path.append( (node_id, ">") )
        visite( dt, right[ node_id ], features, file, org_path )



# structure of model: DecisionTreeClassifier
# https://scikit-learn.org/stable/auto_examples/tree/plot_unveil_tree_structure.html#sphx-glr-auto-examples-tree-plot-unveil-tree-structure-py
dt = pd.read_pickle( inputfile )

# output the tree in a text file, write it
features  = [FEATURE_NAMES[i] for i in dt.tree_.feature]

print("write output to", outputfile)
with open(outputfile,"w") as f:
    # visite the tree from the root which has index = 0
    visite(dt, 0, features, f)