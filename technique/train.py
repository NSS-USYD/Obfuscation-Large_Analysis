# !/usr/bin/env python3
# -*- coding: utf-8 -*-
# ----------------------------------------------------------------------------
# Created By            : xxxxxxxx
# Email                 : xxxxxxxx
# Created Date          : 20/04/2024
# Last Modified Date    : 20/04/2024
# version               : '1.0'
# ---------------------------------------------------------------------------
import torch
import torch.nn as nn
import torch.optim as optim
import torch.nn.functional as F
from torch_geometric.nn import SAGEConv, TopKPooling
from torch_geometric.data import DataLoader
from sklearn.model_selection import train_test_split
import networkx as nx
import matplotlib.pyplot as plt
import numpy as np
from torch_geometric.data import Data
import torch_geometric.nn.pool as pool

import os
import glob
import json
import torch_geometric.transforms as T
from torch_geometric.data import Batch
from tqdm import tqdm
from torch_geometric.data import Data
from torch_geometric.nn import GCNConv
from androguard.misc import AnalyzeAPK
from torch_geometric.data import DataLoader
from sklearn.model_selection import train_test_split
from androguard.core.analysis.analysis import ExternalMethod
from androguard.core.bytecodes.apk import APK
from androguard.core.bytecodes.dvm import DalvikVMFormat
from torch_geometric.nn import MessagePassing, global_add_pool
import re
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay
import xlsxwriter
import pandas as pd
import joblib
import csv

import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from sklearn.neural_network import MLPClassifier

from sklearn.metrics import accuracy_score
# from sklearn.metrics import plot_confusion_matrix
from sklearn.metrics import classification_report
from sklearn.model_selection import GridSearchCV
from sklearn.ensemble import RandomForestClassifier

print("**************************************************************************************************************")
print("************************* APK Level Obfuscation Tool Detector - 20th April 2024 - T1  ************************")
print("**************************************************************************************************************")


def is_readable_string(s):
    # Use a regular expression to check if the string contains only printable characters
    return bool(re.match(r'^[\x20-\x7E]+$', s))


def remove_unreadable_strings(strings):
    cleaned_strings = [s for s in strings if is_readable_string(s)]
    return cleaned_strings


def calculate_average_special_numerical_characters(input_string):
    total_characters = len(input_string)

    if total_characters == 0:
        return 0, 0

    special_characters_count = sum(1 for char in input_string if not char.isalnum())
    numerical_characters_count = sum(1 for char in input_string if char.isnumeric())

    average_special_characters = special_characters_count / total_characters
    average_numerical_characters = numerical_characters_count / total_characters

    return average_special_characters, average_numerical_characters


def calculate_ins_occ(d):
    total = 0
    goto = 0
    invoke = 0
    nop = 0
    if_ins = 0
    move = 0
    # Extract opcodes from each method
    for c in d.get_classes():
        # print(c)
        for m in c.get_methods():
            m.get_name()
            for i in m.get_instructions():
                inst = i.get_name()
                total += 1
                if 'goto' in inst:
                    goto += 1
                elif 'invoke' in inst:
                    invoke += 1
                elif 'nop' in inst:
                    nop += 1
                elif 'if' in inst:
                    if_ins += 1
                elif 'move' in inst:
                    move += 1

    return goto, invoke, nop, if_ins, move, total


def extract_features(apk):
    strings = []
    class_names = []
    method_names = []
    field_names = []
    nop_count = 0
    invoke_count = 0
    move_count = 0
    if_count = 0
    goto_count = 0
    total_ins = 0
    instruction_feature_list = []
    apk_parser = APK(apk)
    dex_files = apk_parser.get_all_dex()
    for dex in dex_files:
        dalvik = DalvikVMFormat(dex)
        tmp_goto, tmp_invoke, tmp_nop, tmp_if_ins, tmp_move, tmp_total = calculate_ins_occ(dalvik)
        nop_count += tmp_nop
        invoke_count += tmp_invoke
        move_count += tmp_move
        if_count += tmp_if_ins
        goto_count += tmp_goto
        total_ins += tmp_total
        for c in dalvik.get_classes():
            class_names.append(os.path.basename(c.get_name()).split('/')[-1].replace(";", ""))
            for m in c.get_methods():
                method_names.append(m.get_name())
            for f in c.get_fields():
                field_names.append(f.get_name())
        for st in dalvik.get_strings():
            strings.append(st)

    instruction_feature_list.append(nop_count * 100 / total_ins)
    instruction_feature_list.append(invoke_count * 100 / total_ins)
    instruction_feature_list.append(move_count * 100 / total_ins)
    instruction_feature_list.append(if_count * 100 / total_ins)
    instruction_feature_list.append(goto_count * 100 / total_ins)

    # Remove <init> and <cinit> from method list
    string_to_remove = "<init>"
    while string_to_remove in method_names:
        method_names.remove(string_to_remove)
    string_to_remove = "<cinit>"
    while string_to_remove in method_names:
        method_names.remove(string_to_remove)

    # Calculate Features for Classes, Methods, and Fields
    # print("###################### CLASSES #############################")
    instruction_feature_list.extend(calculate_avg_occ(class_names))
    # print("###################### METHODS #############################")
    instruction_feature_list.extend(calculate_avg_occ(method_names))
    # print("###################### FIELDS #############################")
    instruction_feature_list.extend(calculate_avg_occ(field_names))
    strings_cleared = remove_unreadable_strings(strings)
    # Convert the filter lists to sets for faster membership testing
    class_names_set = set(class_names)
    method_names_set = set(method_names)
    field_names_set = set(field_names)

    # Use a single list comprehension to filter words
    filtered_words = [word for word in strings_cleared if
                      word not in class_names_set and word not in method_names_set and word not in field_names_set]

    # print("###################### STRINGS #############################")
    instruction_feature_list.extend(calculate_avg_occ(filtered_words))

    return instruction_feature_list


def calculate_avg_occ(list_of_identifiers):
    # Regular expression patterns to match strings with special characters and numeric characters
    special_char_pattern = r'\w*[^\w\s]+\w*'
    numeric_pattern = r'\d'

    feature_list = [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]
    word_lengths = []
    total_word_count = len(list_of_identifiers)
    # print("Total String Count: {}".format(total_word_count))

    # Iterate through the list of strings
    for string in list_of_identifiers:
        word_lengths.append(len(string))
        # print("String - {} | Length - {}".format(string,len(string)))
        if re.search(special_char_pattern, string) and re.search(numeric_pattern, string):
            feature_list[0] += 100 / total_word_count
            # print("Special + Numeric")
        elif re.search(numeric_pattern, string):
            feature_list[1] += 100 / total_word_count
            # print("Numeric")
        elif re.search(special_char_pattern, string):
            feature_list[2] += 100 / total_word_count
            # print("Special")

    for string in list_of_identifiers:
        length = len(string)
        if length == 1:
            feature_list[3] += 100 / total_word_count
        elif length == 2:
            feature_list[4] += 100 / total_word_count
        elif length == 3:
            feature_list[5] += 100 / total_word_count
        elif length == 4:
            feature_list[6] += 100 / total_word_count
        else:
            feature_list[7] += 100 / total_word_count

    return feature_list


def identify_ir_label(apk_file):
    if "proguard" in apk_file:
        lbl = 1
    elif "allatori_001" in apk_file:
        lbl = 1
    elif "allatori_004" in apk_file:
        lbl = 1
    elif "allatori_005" in apk_file:
        lbl = 1
    elif "allatori-default" in apk_file:
        lbl = 1
    elif "dasho_001" in apk_file:
        lbl = 1
    elif "dasho_004" in apk_file:
        lbl = 1
    elif "dasho_005" in apk_file:
        lbl = 1
    elif "dasho_006" in apk_file:
        lbl = 1
    elif "dasho-default" in apk_file:
        lbl = 1
    elif "_IR" in apk_file:
        lbl = 1
    elif "_mix" in apk_file:
        lbl = 1
    else:
        lbl = 0
    return lbl


def identify_cf_label(apk_file):
    if "allatori_001" in apk_file:
        lbl = 1
    elif "allatori_002" in apk_file:
        lbl = 1
    elif "allatori_005" in apk_file:
        lbl = 1
    elif "allatori-default" in apk_file:
        lbl = 1
    elif "dasho_001" in apk_file:
        lbl = 1
    elif "dasho_002" in apk_file:
        lbl = 1
    elif "dasho_004" in apk_file:
        lbl = 1
    elif "dasho_006" in apk_file:
        lbl = 1
    elif "dasho_007" in apk_file:
        lbl = 1
    elif "dasho-default" in apk_file:
        lbl = 1
    elif "_CF" in apk_file:
        lbl = 1
    elif "_mix" in apk_file:
        lbl = 1
    else:
        lbl = 0
    return lbl


def identify_se_label(apk_file):
    if "allatori_001" in apk_file:
        lbl = 1
    elif "allatori_003" in apk_file:
        lbl = 1
    elif "allatori_005" in apk_file:
        lbl = 1
    elif "allatori-default" in apk_file:
        lbl = 1
    elif "dasho_001" in apk_file:
        lbl = 1
    elif "dasho_003" in apk_file:
        lbl = 1
    elif "dasho_005" in apk_file:
        lbl = 1
    elif "dasho_006" in apk_file:
        lbl = 1
    elif "dasho_007" in apk_file:
        lbl = 1
    elif "dasho-default" in apk_file:
        lbl = 1
    elif "_SE" in apk_file:
        lbl = 1
    elif "_mix" in apk_file:
        lbl = 1
    else:
        lbl = 0
    return lbl


def generate_feature_data(apk):
    apk_level_feature_list = extract_features(apk)
    name = os.path.basename(apk).split('/')[-1]
    # all_label = identify_all_label(name)
    ir_label = identify_ir_label(name)
    cf_label = identify_cf_label(name)
    se_label = identify_se_label(name)
    # y = torch.tensor(label_id, dtype=torch.float32).view(1)
    # print("APK : {} | All label {} ".format(name, all_label))
    print("APK : {} | IR label {} ".format(name, ir_label))
    print("APK : {} | CF label {} ".format(name, cf_label))
    print("APK : {} | SE label {} ".format(name, se_label))

    print("APK Level Features: {}".format(apk_level_feature_list))
    text_f.write("APK : {} | IR label {} | CF label {} | SE label {}\n".format(name, ir_label, cf_label, se_label))

    apk_level_feature_list.append(0)

    # all_feature = apk_level_feature_list[:]
    ir_feature = apk_level_feature_list[:]
    cf_feature = apk_level_feature_list[:]
    se_feature = apk_level_feature_list[:]

    # all_feature[37] = all_label
    ir_feature[37] = ir_label
    cf_feature[37] = cf_label
    se_feature[37] = se_label

    return ir_feature, cf_feature, se_feature


def create_model():
    max_iterations = 300
    models = {}
    # Logistic Regression
    from sklearn.linear_model import LogisticRegression
    models['Logistic Regression'] = LogisticRegression(max_iter=max_iterations)
    # Support Vector Machines
    from sklearn.svm import LinearSVC
    models['Support Vector Machines'] = LinearSVC(max_iter=max_iterations)
    # Decision Trees
    from sklearn.tree import DecisionTreeClassifier
    models['Decision Trees'] = DecisionTreeClassifier()
    # Random Forest
    from sklearn.ensemble import RandomForestClassifier
    models['Random Forest'] = RandomForestClassifier()
    # Naive Bayes
    from sklearn.naive_bayes import GaussianNB
    models['Naive Bayes'] = GaussianNB()
    # K-Nearest Neighbors
    from sklearn.neighbors import KNeighborsClassifier
    models['K-Nearest Neighbor'] = KNeighborsClassifier()
    # Ada Boost
    from sklearn.ensemble import AdaBoostClassifier
    models['AdaBoost'] = AdaBoostClassifier()
    # SGD
    from sklearn.linear_model import SGDClassifier
    models['SGD'] = SGDClassifier(max_iter=max_iterations)
    # MLP
    from sklearn.neural_network import MLPClassifier
    models['MLP'] = MLPClassifier(max_iter=max_iterations, hidden_layer_sizes=(150, 100, 50, 25), activation='relu',
                                  solver='adam')

    return models


class MLP(nn.Module):
    def __init__(self, input_dim, hidden_dim, output_dim):
        super(MLP, self).__init__()
        self.lin1 = nn.Linear(input_dim, hidden_dim)  # max pool 32, mean pool 32, apk level features 32
        self.lin2 = nn.Linear(hidden_dim, hidden_dim)
        self.lin3 = nn.Linear(hidden_dim, hidden_dim)
        self.lin4 = nn.Linear(hidden_dim, output_dim)

    def forward(self, data):
        x, edge_index, batch = data.x, data.edge_index, data.batch

        # Basic MLP Layer
        x = F.relu(self.lin1(x))
        x = F.relu(self.lin2(x))
        x = F.relu(self.lin3(x))
        x = self.lin4(x)
        return x


def train_model(model_to_train, epochs, train_data, optimizer, criterion):
    total_losses = []
    final_loss = 0
    for epoch in range(epochs):
        model_to_train.train()
        epoch_loss = 0.0
        for d in train_data:
            optimizer.zero_grad()
            output = model_to_train(d)
            prediction = output.squeeze()
            actual = d.y.squeeze()
            loss = criterion(prediction, actual)
            loss.backward()
            optimizer.step()
            epoch_loss += loss.item()
        avg_epoch_loss = epoch_loss / len(train_data)
        final_loss = avg_epoch_loss
        # print("Epoch : {} | Loss : {}".format(epoch, avg_epoch_loss))
        total_losses.append(avg_epoch_loss)
    return total_losses, final_loss


def save_trained_model(model_to_save, optimizer, criterion, name):
    torch.save({
        'model_state_dict': model_to_save.state_dict(),
        'optimizer_state_dict': optimizer.state_dict(),
        'criterion_state_dict': criterion.state_dict(),
    }, name)


def evaluate_model(model_to_validate, test_data):
    local_predictions = []
    local_labels = []

    with torch.no_grad():
        correct_pred = 0
        total_pred = 0
        for data in test_data:
            output = model_to_validate(data)
            predicted_label = (torch.sigmoid(output.squeeze()) > 0.5).float()
            local_predictions.append(predicted_label.item())
            local_labels.append(data.y.item())
            total_pred += 1
            correct_pred += (predicted_label == data.y).sum().item()
            # print("No: {} | Actual : {} | Prediction : {}".format(total_pred, data.y, predicted_label))
        # acc = correct_pred / total_pred
        c_matrix = confusion_matrix(local_labels, local_predictions)
        TP = c_matrix[1][1]
        TN = c_matrix[0][0]
        FP = c_matrix[0][1]
        FN = c_matrix[1][0]
        print("TP- {} | TN- {} | FP- {} | FN- {}".format(TP, TN, FP, FN))
        acc = accuracy_score(local_labels, local_predictions)
        precision = precision_score(local_labels, local_predictions)
        recall = recall_score(local_labels, local_predictions)
        f1 = f1_score(local_labels, local_predictions)
        print("Confusion Matrix : {}".format(c_matrix))
        print("Accuracy: {}".format(acc))
        print("Precision: {}".format(precision))
        print("Recall: {}".format(recall))
        print("F1: {}".format(f1))
        print(classification_report(local_labels, local_predictions))
    return [TP, TN, FP, FN, acc * 100, precision, recall, f1]


def plot_loss(epoch_num, losses, plot_title):
    # Plot the training loss
    plt.plot(range(1, epoch_num + 1), losses, label='Training Loss')
    plt.xlabel('Epoch')
    plt.ylabel('Loss')
    plt.title(plot_title)
    plt.legend()
    plt.show()


def create_txt_file(file_path, data):
    print("Generating Text File")
    file = open(file_path, 'w')
    file.write(data + '\n')
    file.close()


def perform_model_generation(model_name, rf_classifier, param_grid, cross_validation, trainX, trainY, testX, testY):
    print("Working on Model: {}".format(model_name))

    grid_search = GridSearchCV(estimator=rf_classifier, param_grid=param_grid, cv=cross_validation)
    grid_search.fit(trainX, trainY)

    # Get the best parameters and best score
    best_params = grid_search.best_params_
    best_score = grid_search.best_score_

    print("Best Parameters:", best_params)
    print("Best Score:", best_score)
    grid_predictions = grid_search.predict(testX)
    print(classification_report(testY, grid_predictions))

    # Train the best model using the best parameters on the entire dataset
    best_model = grid_serach.best_estimator_
    
    predictions = best_model.predict(testX)
    print(classification_report(testY, predictions))

    # Save the best model
    joblib.dump(best_model, WORKING_DIR + '/best_RF_Model_' + model_name + '-V1.pkl')


if __name__ == "__main__":

    APK_PATH = "D7"

    WORKING_DIR = 'Add your working directory here'

    TXT_LOG_PATH = WORKING_DIR + "experiment.txt"

    FEATURE_PATH_IR = WORKING_DIR + 'IR_V1.csv'
    FEATURE_PATH_CF = WORKING_DIR + 'CF_V1.csv'
    FEATURE_PATH_SE = WORKING_DIR + 'SE_V1.csv'

    data_list_ir = []
    data_list_cf = []
    data_list_se = []
    data_to_excel = []

    is_initial_training = True

    data_list_ir = []
    data_list_cf = []
    data_list_se = []
    data_to_excel = []

    tot = 0
    if is_initial_training:
        header_values = ["avg_nop", "avg_invoke", "avg_move", "avg_if", "avg_goto", "avg_class_num_char",
                         "avg_class_num", "avg_class_char", "avg_class_l1", "avg_class_l2", "avg_class_l3",
                         "avg_class_l4", "avg_class_ln", "avg_method_num_char", "avg_method_num", "avg_method_char",
                         "avg_method_l1", "avg_method_l2", "avg_method_l3", "avg_method_l4", "avg_method_ln",
                         "avg_field_num_char", "avg_field_num", "avg_field_char", "avg_field_l1", "avg_field_l2",
                         "avg_field_l3", "avg_field_l4", "avg_field_ln", "avg_string_num_char", "avg_string_num",
                         "avg_string_char", "avg_string_l1", "avg_string_l2", "avg_string_l3", "avg_string_l4",
                         "avg_string_ln", "label"]

        text_f = open(TXT_LOG_PATH, 'w')
        for _ in glob.iglob(APK_PATH + '**/*.apk', recursive=True):
            tot += 1
        with tqdm(total=tot) as pbar:
            for apk_file in glob.iglob(APK_PATH + '**/*.apk', recursive=True):
                file_name = os.path.basename(apk_file).split('/')[-1]
                print(file_name)
                feature_ir, feature_cf, feature_se = generate_feature_data(apk_file)
                data_list_ir.append(feature_ir)
                data_list_cf.append(feature_cf)
                data_list_se.append(feature_se)
                pbar.update(1)
        with open(FEATURE_PATH_IR, "w", newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(header_values)
            writer.writerows(data_list_ir)
        with open(FEATURE_PATH_CF, "w", newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(header_values)
            writer.writerows(data_list_cf)
        with open(FEATURE_PATH_SE, "w", newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(header_values)
            writer.writerows(data_list_se)

    print("Data List Creation Finish")

    df = pd.read_csv(FEATURE_PATH_IR)
    x_ir = df.drop('label', axis=1)
    y_ir = df['label']
    print(df['label'].value_counts())
    trainX_ir, testX_ir, trainY_ir, testY_ir = train_test_split(x_ir, y_ir, test_size=0.2)

    df = pd.read_csv(FEATURE_PATH_CF)
    x_cf = df.drop('label', axis=1)
    y_cf = df['label']
    print(df['label'].value_counts())
    trainX_cf, testX_cf, trainY_cf, testY_cf = train_test_split(x_cf, y_cf, test_size=0.2)

    df = pd.read_csv(FEATURE_PATH_SE)
    x_se = df.drop('label', axis=1)
    y_se = df['label']
    print(df['label'].value_counts())
    trainX_se, testX_se, trainY_se, testY_se = train_test_split(x_se, y_se, test_size=0.2)

    print("Creating Models")

    param_grid = {
        'n_estimators': [10, 20, 30, 40, 50, 60, 70, 80, 90, 100],
        'max_depth': [None, 2, 5, 10, 20, 30],
        'min_samples_split': [2, 3, 4, 5, 6],
        'min_samples_leaf': [1, 2, 4, 8, 16],
        'max_features': ['sqrt', 'log2'],
        'bootstrap': [True, False],
        'criterion': ['gini', 'entropy'],
        'class_weight': [None, 'balanced'],
        'random_state': [42]  # fixed random state for reproducibility
    }

    rf_classifier_ir = RandomForestClassifier()
    rf_classifier_cf = RandomForestClassifier()
    rf_classifier_se = RandomForestClassifier()

    # IR
    perform_model_generation('IR', rf_classifier_ir, param_grid, 3, trainX_ir, trainY_ir, testX_ir, testY_ir)

    # CF
    perform_model_generation('CF', rf_classifier_cf, param_grid, 3, trainX_cf, trainY_cf, testX_cf, testY_cf)

    # SE
    perform_model_generation('SE', rf_classifier_se, param_grid, 3, trainX_se, trainY_se, testX_se, testY_se)

    #######################################################################
