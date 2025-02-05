is link to download the ## State of Obfuscation

<div align="center">
    <img src="/BD.png" width="900" height="400" alt="overall architecure"/>
</div>

In this repository, we provide the source code for the Machine Learning models used in our research paper, along with their best models. We also include the script used for the large-scale analysis after combining the best models. Additionally, we provide basic steps for training and validating the models and details on the datasets used.

**Ground-Truth Datasets:** [External Link to the Dataset]((https://unsw my.sharepoint.com/:f:/g/personal/z5429691_ad_unsw_edu_au/ErEx7ht7XZhGuS2frV16j5UBBJvHxZuIou1ARFu27SLHUw?e=qjysgZ))
Use this link to download the D1-D9 datasets for training and validating models.


This repository consists of four main sub-folders
- obfuscation: Obfuscation Detector
- tool: Obfuscation Tool Detector
- technique: Obfuscation Tech Detector
- large-scale: Large Scale Investigator

# Using the Source Codes

First, clone the git repo.
```
git clone https://github.com/NSS-USYD/Obfuscation-Large_Analysis.git
```

Before moving to run any of the modules need to create a virtual environment to make sure all the modules will run without any hassle
Before moving forward make sure you have the basic requirements: Python, and Pip installed

```sh
cd Obfuscation-Large_Analysis
pip install virtualenv
virtual env venv
source venv/bin/activate
```
Within the virtual environment, need to install the required packages
```sh
pip install androguard == 3.3.5
pip install torch torchvision torchaudio
pip install joblib
pip install networkx
pip install matplotlib
pip install tqdm
pip install pandas
pip install sklearn
pip install xlsxwriter
pip install openpyxl
```

## Obfuscation Detector
```sh
cd obfuscation
```
**Note:**
Download the D1-D8 Datasets from the above Ground-Truth Dataset folder and save them in the data folder

train.py will train a new model and provide you with the results outputs based on a few hyperparameters. 
For the training process, this module will use the D1 Dataset.

For validation use D2, D3, D4 datasets

## Obfuscation Tool Detector
```sh
cd tool
```
Similar to Obfuscation Detector train.py will tune the hyperparameters of the bank of classifiers (ProGuard vs. Other, DashO vs. Other, and Allatori vs. Other)
Change the 'WORKING_DIR' according to your environment inside train.py
For the training process, this module will use the D5 Dataset
This module will create three distinct models after finding the best parameters for aforementioned three classifiers which we can use to further validate

validate.py inside will validate the created modules
Change the 'WORKING_DIR', PROGUARD_MODEL_PATH, DASHO_MODLE_PATH and ALLATORI_MODEL_PATH according to your environment and saved best models inside validate.py

The validation set is D6.

## Obfuscation Technique Detector
```sh
cd technique
```
The Training and validation for this classifier is as same as the Tool Detector. Change the WORKING_DIR and run the train.py module to create features and train the classifiers with hyperparameter tuning. This module will create three models to handle Obfuscation Technique detection (IR, CF, and SE)
The dataset to Train and test is the D7 dataset

validate.py inside will validate the created modules
Change the 'WORKING_DIR', IR_MODEL_PATH, CF_MODLE_PATH and SE_MODEL_PATH according to your environment and saved best models inside validate.py
Use D8 and D9 as validation datasets

# Improtant:

- We have provided with the Best Models which we created to use in our Large Scale Investigation. Anyone can use those Bestmodels and change the Model Names accordingly in validate.py and validate with your own APK dataset.


## Large Scale Investigation
```sh
cd large_scale
```
-Best models are in BestModels Folder

analyser.py was designed to conduct a large-scale investigation of APKs downloaded from the Google Play Store.

We have kept a record of our APK Files as a .csv (we have provided an example csv - change it according to your dataset) and we read through csv file and create the APK file path for each and every APK.

Before running analyser.py please change the below congifs inside analyser.py accordingly.
In addition, add APK paths inside the example_apk_file.csv file
```sh
WORKING_DIR = "Add your working directory"
OBFUSCATION_MODEL_NAME = "Obfuscation Detector Model Name"
PROGUARD_MODEL_NAME = "ProGuard Model Name"
DASHO_MODEL_NAME = "DashO Model Name"
ALLATORI_MODEL_NAME = "Allatori Model Name"
IR_MODEL_NAME = "IR Model Name"
CF_MODEL_NAME = "CF Model Name"
SE_MODEL_NAME = "SE Model Name
APK_FILE = "example_apk_file.csv"
server_path = 'Create your APK path'
```
All the available APKs will be analysed and the final report will be created which can be used to extract the analysis results.
