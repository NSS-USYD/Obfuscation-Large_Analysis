# State of Obfuscation: Machine Learning-Based Obfuscation Analysis

<div align="center">
    <img src="/BD.png" width="900" height="400" alt="overall architecture"/>
</div>

This repository contains the source code and trained models used in our research on large-scale Android obfuscation analysis. It includes:

- Machine Learning models and best-performing checkpoints  
- Scripts for large-scale APK analysis and reporting  
- Training and validation instructions  
- Dataset information and usage guidelines  

## 📁 Ground-Truth Datasets

Download datasets **D1–D9** from the link below. These are used for model training, validation, and experiments.

👉 **[Download Dataset (D1–D9)](https://unsw-my.sharepoint.com/:f:/g/personal/z5429691_ad_unsw_edu_au/ErEx7ht7XZhGuS2frV16j5UBBJvHxZuIou1ARFu27SLHUw?e=RYUffn)**

## 📂 Repository Structure

| Folder | Description |
|--------|--------------|
| `obfuscation/` | Obfuscation Detector (Binary Classifier) |
| `tool/` | Obfuscation Tool Detector (ProGuard, DashO, Allatori) |
| `technique/` | Technique Detector (Identifier Renaming, Control Flow, String Encryption) |
| `large_scale/` | Large-Scale APK Investigator |

---

# 🚀 Setup Instructions

Clone the repository:

```sh
git clone https://github.com/NSS-USYD/Obfuscation-Large_Analysis.git
cd Obfuscation-Large_Analysis
```

Create & activate a virtual environment:

```sh
pip install virtualenv
virtualenv venv
source venv/bin/activate
```

Install dependencies:

```sh
pip install androguard==3.3.5
pip install torch torchvision torchaudio
pip install joblib networkx matplotlib tqdm pandas sklearn xlsxwriter openpyxl
```

---

# 📌 Module Usage

### 1️⃣ Obfuscation Detector
```sh
cd obfuscation
```
- Place datasets **D1–D4** in `data/`
- Train a new model:
```sh
python train.py
```

### 2️⃣ Tool Detector
```sh
cd tool
```
- Uses dataset **D5** for training and **D6** for validation  
- Update paths in `train.py` and `validate.py`  
- Trains 3 models: **ProGuard / DashO / Allatori**

### 3️⃣ Technique Detector
```sh
cd technique
```
- Uses **D7–D9** for training and testing  
- Detects: IR / CF / SE  
- Update paths in scripts before running

### 4️⃣ 🔎 Large Scale Investigation
```sh
cd large_scale
```
Configure model names & paths in `analyser.py`:

```sh
WORKING_DIR = "path"
OBFUSCATION_MODEL_NAME = "model_name"
PROGUARD_MODEL_NAME = "model_name"
DASHO_MODEL_NAME = "model_name"
ALLATORI_MODEL_NAME = "model_name"
IR_MODEL_NAME = "model_name"
CF_MODEL_NAME = "model_name"
SE_MODEL_NAME = "model_name"
APK_FILE = "example_apk_file.csv"
server_path = "apk_directory"
```

Run large-scale analysis:

```sh
python analyser.py
```

---

# Model Hyperparameters

## MLP – Obfuscation Detection
| Hyperparameter | Values Explored |
|----------------|------------------|
| Input dimension | 37 |
| Hidden dimension | 16, 32, 64, 128 |
| Output dimension | 1 |
| Learning rate | 1e-6 → 5e-2 (log scale) |
| Epochs | 1000 → 5000 |
| Loss | BCEWithLogitsLoss |
| Optimizer | Adam |

**Best Model Selected:**  
Hidden **32**, LR **1e-3**, **5000 epochs**, **3-fold CV on D1**.

---

## Random Forest – Tool & Technique Detection
| Hyperparameter | Values Explored |
|----------------|------------------|
| n_estimators | 10–100 |
| max_depth | None, 2, 5, 10, 20, 30 |
| min_samples_split | 2–8 |
| min_samples_leaf | 1, 2, 4, 8, 16 |
| max_features | sqrt, log2 |
| bootstrap | True, False |
| criterion | gini, entropy |
| class_weight | None, balanced |
| random_state | 42 |

### Best Configuration per Classifier
| Classifier | n_estimators | max_depth | split | leaf | features | bootstrap | criterion | class_weight |
|------------|--------------|-----------|--------|-------|----------|------------|------------|---------------|
| Allatori | 30 | None | 3 | 1 | sqrt | True | gini | None |
| DashO | 10 | None | 2 | 1 | sqrt | True | gini | None |
| ProGuard | 30 | None | 2 | 1 | log2 | True | entropy | None |
| CF | 40 | 5 | 2 | 2 | log2 | True | entropy | None |
| IR | 20 | 2 | 2 | 4 | sqrt | False | gini | None |
| SE | 20 | None | 2 | 8 | log2 | True | gini | balanced |

---

# 📄 Citation

If you use our code or datasets, please cite our paper (to be added once published).

---

# 🤝 Acknowledgements

This project is developed as part of ongoing research at **The University of New South Wales**.

---

# 📬 Contact

For issues or collaborations:

📧 a.pothpitiyage_don@unsw.edu.au  

---

# ⭐️ Support

If you find this useful, please **star the repository** ⭐
