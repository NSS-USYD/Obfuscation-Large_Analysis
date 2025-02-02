# !/usr/bin/env python3
# -*- coding: utf-8 -*-
# ----------------------------------------------------------------------------
# Created By            : xxxxxx
# Email                 : xxxxxx
# Created Date          : 26/03/2024
# Last Modified Date    : 26/03/2024
# version               : '1.0'
# ---------------------------------------------------------------------------

import re
import os
import glob
import json
import joblib
import torch
import xlsxwriter
import pandas as pd

import torch.nn as nn
import torch.optim as optim
import torch.nn.functional as F
from torch_geometric.data import DataLoader
from sklearn.model_selection import train_test_split
import networkx as nx
import matplotlib.pyplot as plt
import numpy as np
from torch_geometric.data import Data
import torch_geometric.nn.pool as pool
import torch_geometric.transforms as T
from torch_geometric.data import Batch
from tqdm import tqdm
from torch_geometric.nn import GCNConv
from androguard.misc import AnalyzeAPK
from torch_geometric.data import DataLoader
from sklearn.model_selection import train_test_split
from androguard.core.analysis.analysis import ExternalMethod
from androguard.core.bytecodes.apk import APK
from androguard.core.bytecodes.dvm import DalvikVMFormat
from torch_geometric.nn import MessagePassing, global_add_pool
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay
from sklearn.metrics import classification_report

print("*******************************************************************************************")
print("********************* APK Level Feature Based Obfuscation Classifier  *********************")
print("*******************************************************************************************")


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

    instruction_feature_list.append(nop_count * 100/total_ins)
    instruction_feature_list.append(invoke_count * 100/total_ins)
    instruction_feature_list.append(move_count * 100/total_ins)
    instruction_feature_list.append(if_count * 100/total_ins)
    instruction_feature_list.append(goto_count * 100/total_ins)

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


def identify_label(apk_file):
    if "Reflection" in apk_file:
        lbl = 1
    elif "allatori" in apk_file:
        lbl = 1
    elif "dasho" in apk_file:
        lbl = 1
    elif "proguard" in apk_file:
        lbl = 1
    elif "Encrypted" in apk_file:
        lbl = 1
    else:
        lbl = 0
    return lbl


def generate_feature_data(apk):
    apk_level_feature_list = extract_features(apk)
    name = os.path.basename(apk).split('/')[-1]
    label_id = identify_label(name)
    y = torch.tensor(label_id, dtype=torch.float32).view(1)
    print("APK : {} | label {} ".format(name, label_id))
    print("APK Level Features: {}".format(apk_level_feature_list))
    text_f.write("APK : {} | label {} \n".format(name, label_id))

    apk_level_features = torch.tensor(apk_level_feature_list)
    only_feature_with_label = Data(x=apk_level_features, y=y)
    torch.save(only_feature_with_label, FEATURE_PATH + "/" + file_name + ".pt")
    return only_feature_with_label


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


if __name__ == "__main__":

    APK_PATH = "D1"
    FEATURE_PATH = "Add_Path_To_Save_Feature_File"

    TXT_LOG_PATH = "experiment_details.txt"
    TRAIN_TEST_RESULTS = 'Initial_Train-Data.xlsx'

    is_initial_training = True # True for Initial Feature Extraction
    load_model = False
    is_testing = False

    input_dim_feature_only = 37  # Number of features per node
    hidden_dim = 32
    output_dim = 1
    learning_rate = 0.001
    num_epochs = 5000
    lr_list = [0.000001, 0.000005, 0.00001, 0.00005, 0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05]

    data_list = []
    data_to_excel = []

    tot = 0
    if is_initial_training:
        text_f = open(TXT_LOG_PATH, 'w')
        for _ in glob.iglob(APK_PATH + '**/*.apk', recursive=True):
            tot += 1
        print(tot)
        with tqdm(total=tot) as pbar:
            for apk_file in glob.iglob(APK_PATH + '**/*.apk', recursive=True):
                file_name = os.path.basename(apk_file).split('/')[-1]
                print(file_name)
                feature = generate_feature_data(apk_file)
                data_list.append(feature)
                pbar.update(1)
    else:
        print("READING FROM THE CREATED FEATURES")
        tot = 0
        for _ in glob.iglob(FEATURE_PATH_C + '**/*.pt', recursive=True):
            tot += 1
        with tqdm(total=tot) as pbar:
            for feature_file in glob.iglob(FEATURE_PATH_C + '**/*.pt', recursive=True):
                file_name = os.path.basename(feature_file).split('/')[-1]
                print("Feature File Name: {}".format(file_name))
                data_read = torch.load(feature_file)
                data_list.append(data_read)
                pbar.update(1)

    print("Data List Creation Finish")
    train_data_feat, test_data_feat = train_test_split(data_list, test_size=0.2, random_state=42)

    print("Creating Models")
    count = 0
    workbook = xlsxwriter.Workbook(TRAIN_TEST_RESULTS)
    worksheet = workbook.add_worksheet()

    #######################################################################
    for lr in lr_list:
        model_mlp = MLP(input_dim_feature_only, hidden_dim, output_dim)
        model_mlp_name = 'MLP-Train-Default-' + str(lr) + '.pth'
        optimizer_mlp = optim.Adam(model_mlp.parameters(), lr=lr)
        criterion_mlp = nn.BCEWithLogitsLoss()

        print("Training the Model : {}".format(model_mlp_name))
        train_losses_mlp, last_loss = train_model(model_mlp, num_epochs, train_data_feat, optimizer_mlp, criterion_mlp)
        save_trained_model(model_mlp, optimizer_mlp, criterion_mlp, model_mlp_name)
        label = 'loss of: {} LR {}'.format(model_mlp_name, lr)
        plt.clf()
        plt.plot(range(1, num_epochs + 1), train_losses_mlp, label=label)
        to_excel = [model_mlp_name, learning_rate, last_loss]
        return_list = evaluate_model(model_mlp, test_data_feat)
        to_excel.extend(return_list)
        worksheet.write_row(count, 0, to_excel)
        count += 1

        plt.xlabel('Epoch')
        plt.ylabel('Loss')
        plt.title('MLP with APK Features - LR-{}'.format(lr))
        plt.legend()
        plt.savefig('Model:-{}{}.png'.format(model_mlp_name, '_loss_plot'))

    workbook.close()

    
