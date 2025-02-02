# State of Obfuscation
This artifact folder is consist with four main modules
- Obfuscation Detector
- Obfuscation Tool Detector
- Obfuscation Tech Detector
- Large Scale Investigator

Before moving to run any of the module need to create a virtual environment to make sure all the modules will run without any hassle
Before moving forward make sure you have basic requirements: Python, and Pip installed

```sh
cd Artifacts
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
cd Artifacts/1-ObfuscationDetector
```
train_and_test.py inside 1-ObfuscationDetector folder will train a new model and provide you with the results outputs based on few hyperparameters. 
For the training process this module will use Dataset inside D1 folder

## Obfuscation Tool Detector
```sh
cd Artifacts/2-ObfuscationToolDetector
```
Similar to Obfuscation Detector train_and_test.py will tune the hayper parameters of bank of classifiers (ProGuard vs. Other, DashO vs. Other, and Allatori vs. Other)
Change the 'WORKING_DIR' according to your environment inside train_and_test.py
For the training process this module will use Dataset inside D5 folder
This module will create three distinct models after finding the best parameters for aforementioned three classifiers which we can use to further validate

validate.py inside will do the validation for the created modules
Change the 'WORKING_DIR', PROGUARD_MODEL_PATH, DASHO_MODLE_PATH and ALLATORI_MODEL_PATH according to your environment and saved best models inside validate.py

The validation set is inside D6 Folder for your reference.

## Obfuscation Technique Detector
```sh
cd Artifacts/3-ObfuscationToolDetector
```
The Training and validation for this classifer is as same as the Tool Detector. Change the WORKING_DIR annd run the train_and_test.py module to create features and train the classifiers with hyperparameter tuning. This module will create three models to handle Obfuscation Technique detection (IR,CF, and SE)
Dataset to Train and test is inside D7 folder for your reference

validate.py inside will do the validation for the created modules
Change the 'WORKING_DIR', IR_MODEL_PATH, CF_MODLE_PATH and SE_MODEL_PATH according to your environment and saved best models inside validate.py

# Improtant
- For Above Three Classifiers, due to the double-blind policy we cannot provide with the Manually Created APKs to do the initial training (APKs signed with the use of Main AUthor's credentials)
- We have provided with the Best Models which we created to use in our Large Scale Investigation. Anyone can use those Bestmodels and change the Model Names accordingle in validate.py and validate with your own APK dataset.
- We will provide the APK data set upon the acceptance of the paper.

## Large Scale Investigation
```sh
cd Artifacts/4-LargeScaleInvestigator
```
-Bestmodels are in BestModels Folder

analyser.py was designed to conduct a large-scale investigation of APKs downloaded from the Google Play Store.
We have kept a record of our APK Files as a .csv (we have provided an example csv - change it according to your dataset) and we read through csv file and create the APK file path for each and every APK.

Before running analyser.py please change below congifs inside analyser.py accordingly.
In addition, add apk paths inside the example_apk_file.csv file
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
All the available APKs will be analysed and final report will be created which can be used to extract the analysis results.
