# !/usr/bin/env python3
# -*- coding: utf-8 -*-
# ----------------------------------------------------------------------------
# Created By            : xxxxx
# Email                 : xxxxx
# Created Date          : 27/03/2024
# Last Modified Date    : 27/03/2024
# version               : '1.0'
# ---------------------------------------------------------------------------

import os
import glob
import joblib
import torch
import re
import torch.optim as optim
import torch.nn.functional as F
import xlsxwriter

from tqdm import tqdm
import torch.nn as nn
from androguard.core.bytecodes.apk import APK
from androguard.core.bytecodes.dvm import DalvikVMFormat
from torch_geometric.data import Data
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay
from sklearn.metrics import classification_report
import numpy as np
import pandas as pd

print("*******************************************************************************************")
print("**************** APK Level Feature Based Obfuscation Technique Classifier  ****************")
print("*******************************************************************************************")


def is_readable_string(s):
    # Use a regular expression to check if the string contains only printable characters
    return bool(re.match(r'^[\x20-\x7E]+$', s))


def remove_unreadable_strings(strings):
    cleaned_strings = [s for s in strings if is_readable_string(s)]
    return cleaned_strings


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


def generate_feature_data_with_label(apk):
    apk_level_feature_list = extract_features(apk)
    name = os.path.basename(apk).split('/')[-1]

    ir_label = identify_ir_label(name)
    cf_label = identify_cf_label(name)
    se_label = identify_se_label(name)

    print("APK : {} | IR label {} ".format(name, ir_label))
    print("APK : {} | CF label {} ".format(name, cf_label))
    print("APK : {} | SE label {} ".format(name, se_label))

    print("APK Level Features: {}".format(apk_level_feature_list))
    text_file.write("APK : {} | ir_label {} | cf_label {} | se_label {} \n".format(name, ir_label, cf_label, se_label))

    return apk_level_feature_list, ir_label, cf_label, se_label


def generate_feature_data(apk):
    apk_level_feature_list = extract_features(apk)
    name = os.path.basename(apk).split('/')[-1]
    print("APK : {} ".format(name))
    print("APK Level Features: {}".format(apk_level_feature_list))

    apk_level_features = torch.tensor(apk_level_feature_list)
    only_feature = Data(x=apk_level_features)
    # Uncomment If you want to save the features
    # torch.save(only_feature_with_label, FEATURE_PATH + "/" + file_name + ".pt")
    return only_feature


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


def calculate_results(model_n, lbl, predictors):
    print("Model: {}".format(model_n))
    con_mat = confusion_matrix(lbl, predictors)
    print(con_mat)
    tp = con_mat[1][1]
    tn = con_mat[0][0]
    fp = con_mat[0][1]
    fn = con_mat[1][0]
    a = accuracy_score(lbl, predictors)
    p = precision_score(lbl, predictors)
    r = recall_score(lbl, predictors)
    f = f1_score(lbl, predictors)
    print(classification_report(lbl, predictors))
    out_data = "Model Name- {} | TP- {} | TN- {} | FP- {} | FN- {} | ACC- {} | Precision- {} | Recall- {} | F1- {}\n" \
        .format(model_n, 0, 0, 0, 0, 0, 0, 0, 0)
    return out_data


if __name__ == "__main__":

    APK_PATH = "D8"

    WORKING_DIR = "Add Your working directory here"

    IR_MODEL_PATH = WORKING_DIR + "IR Model Name"
    CF_MODEL_PATH = WORKING_DIR + "CF Model Name"
    SE_MODEL_PATH = WORKING_DIR + "SE Model Name"
    LOG_FILE = WORKING_DIR + "/validation.txt"
    EXCEL_FILE = WORKING_DIR + '/Validation_Results.xlsx'

    tot = 0

    labels_ir = []
    predictions_ir = []

    labels_cf = []
    predictions_cf = []

    labels_se = []
    predictions_se = []

    outcome = []
    pre_trained_models = {}

    # Loading Models
    model_ir = joblib.load(IR_MODEL_PATH)
    model_cf = joblib.load(CF_MODEL_PATH)
    model_se = joblib.load(SE_MODEL_PATH)

    text_file = open(LOG_FILE, 'w')
    workbook = xlsxwriter.Workbook(EXCEL_FILE)
    worksheet = workbook.add_worksheet()

    header = ['APK_Name',
              'Actual_IR_Label', 'Predicted_IR_Label', 'Probability',
              'Actual_CF_Label', 'Predicted_CF_Label', 'Probability',
              'Actual_SE_Label', 'Predicted_SE_Label', 'Probability']
    row_number = 0
    worksheet.write_row(row_number, 0, header)

    for _ in glob.iglob(APK_PATH + '**/*.apk', recursive=True):
        tot += 1
    with tqdm(total=tot) as pbar:
        header_values = ["avg_nop", "avg_invoke", "avg_move", "avg_if", "avg_goto", "avg_class_num_char",
                         "avg_class_num", "avg_class_char", "avg_class_l1", "avg_class_l2", "avg_class_l3",
                         "avg_class_l4", "avg_class_ln", "avg_method_num_char", "avg_method_num", "avg_method_char",
                         "avg_method_l1", "avg_method_l2", "avg_method_l3", "avg_method_l4", "avg_method_ln",
                         "avg_field_num_char", "avg_field_num", "avg_field_char", "avg_field_l1", "avg_field_l2",
                         "avg_field_l3", "avg_field_l4", "avg_field_ln", "avg_string_num_char", "avg_string_num",
                         "avg_string_char", "avg_string_l1", "avg_string_l2", "avg_string_l3", "avg_string_l4",
                         "avg_string_ln"]
        for apk_file in glob.iglob(APK_PATH + '**/*.apk', recursive=True):
            file_name = os.path.basename(apk_file).split('/')[-1]
            print("APK : {}".format(file_name))
            row_number += 1
            # Extract Features
            apk_feature, label_ir, label_cf, label_se = generate_feature_data_with_label(apk_file)

            temp_df = pd.DataFrame([apk_feature], columns=header_values)

            labels_ir.append(label_ir)
            labels_cf.append(label_cf)
            labels_se.append(label_se)

            ir_probabilty = model_ir.predict_proba(temp_df)
            ir_prediction = model_ir.predict(temp_df)

            print("APK: {} | IR True Label {} | IR Label {} | Probabilty {}".format(file_name, label_ir, ir_prediction,
                                                                                    ir_probabilty))

            cf_probabilty = model_cf.predict_proba(temp_df)
            cf_prediction = model_cf.predict(temp_df)

            print("APK: {} | CF True Label {} | Predicted Label {} | Probabilty {}".format(file_name, label_cf,
                                                                                           cf_prediction,
                                                                                           cf_probabilty))

            se_probabilty = model_se.predict_proba(temp_df)
            se_prediction = model_se.predict(temp_df)

            print("APK: {} | SE True Label {} | SE Label {} | Probabilty {}".format(file_name, label_se, se_prediction,
                                                                                    se_probabilty))

            predictions_ir.append(ir_prediction)
            predictions_cf.append(cf_prediction)
            predictions_se.append(se_prediction)

            excel_list = [file_name,
                          label_ir, ir_prediction, ir_probabilty[0, 1],
                          label_cf, cf_prediction, cf_probabilty[0, 1],
                          label_se, se_prediction, se_probabilty[0, 1]]

            worksheet.write_row(row_number, 0, excel_list)

            text_file.write("APK {}\n".format(file_name))
            text_file.write("Actual IR Label {} | CF Label {} | SE Label {}\n".format(label_ir, label_cf, label_se))
            text_file.write("IR {} | CF {} | SE {}\n".format(ir_prediction, cf_prediction, se_prediction))
            text_file.write("\n")

            pbar.update(1)

    text_file.write("{}\n".format(calculate_results('model_ir', labels_ir, predictions_ir)))
    text_file.write("{}\n".format(calculate_results('model_cf', labels_cf, predictions_cf)))
    text_file.write("{}\n".format(calculate_results('model_se', labels_se, predictions_se)))

    workbook.close()
