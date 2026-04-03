# 🔍 IntelliPort — AI Powered Port Scanner
### 4th Semester Project | Cybersecurity + Artificial Intelligence

---

## 📁 Project Files

| File | Purpose |
|------|---------|
| `intelliport_gui.py` | ⭐ Main application (run this to start) |
| `scanner.py` | Port scanning engine (socket-based) |
| `ai_predictor.py` | AI risk prediction module |
| `train_model.py` | Trains and saves the AI model |
| `intelliport_dataset.csv` | Training dataset (80+ port records) |
| `requirements.txt` | Python library dependencies |

---

## ⚙️ Setup Instructions (Step by Step)

### Step 1 — Install Python
Download Python 3.8+ from https://python.org
Make sure to check ✅ "Add Python to PATH" during install.

### Step 2 — Install Required Libraries
Open Command Prompt / Terminal in the project folder and run:
```
pip install -r requirements.txt
```

### Step 3 — Train the AI Model (Only Once!)
```
python train_model.py
```
This creates two files:
- `intelliport_model.pkl` (the trained AI)
- `intelliport_encoders.pkl` (text encoders)

### Step 4 — Launch the Application
```
python intelliport_gui.py
```

---

## 🖥️ How to Use

1. Enter a **Target IP address** (e.g., 127.0.0.1 for your own computer)
2. Select **port range**: Common Ports / Top 1000 / Custom
3. Click **▶ START SCAN**
4. Watch results appear in real-time with AI risk ratings:
   - 🟢 **Safe** — No action needed
   - 🟡 **Suspicious** — Monitor this port
   - 🔴 **Dangerous** — Close or restrict immediately
5. View the **Threat Score** (0–100) at the bottom
6. Click **💾 EXPORT CSV** to save results

---

## 🤖 How the AI Works

1. **Dataset**: 80+ records of ports with known risk levels
2. **Features**: Port number, Protocol (TCP/UDP), Status (open/closed/filtered)
3. **Algorithm**: Random Forest Classifier (100 decision trees)
4. **Output**: Risk Level — 0 (Safe), 1 (Suspicious), 2 (Dangerous)

### AI Training Flow:
```
CSV Dataset → Label Encoding → Train/Test Split
     → Random Forest Model → Accuracy Check → Save Model
```

### Prediction Flow:
```
Scanned Port → Encode Features → Load Model → Predict Risk → Show in GUI
```

---

## 🛠️ Technologies Used

| Component | Technology |
|-----------|-----------|
| Language | Python 3.8+ |
| Port Scanning | socket (built-in) |
| Multi-threading | threading (built-in) |
| AI / ML | scikit-learn (Random Forest) |
| Data Processing | pandas, numpy |
| GUI | tkinter (built-in) |
| Dataset | CSV (custom) |

---

## 🔬 System Architecture

```
User Input (Target IP + Port Range)
           ↓
    Port Scanner Module
    (socket connections)
           ↓
   Service Detection
   (port → service map)
           ↓
   AI Analysis Module
   (Random Forest Model)
           ↓
   Risk Prediction
   (Safe / Suspicious / Dangerous)
           ↓
   Threat Score Calculation
   (0–100 overall score)
           ↓
   Tkinter GUI Dashboard
   (real-time results table)
```

---

## ⚖️ Legal & Ethical Notice

> ⚠️ **Only scan systems you own or have explicit permission to scan.**
> Unauthorized port scanning may be illegal in your region.
> This tool is for educational and authorized security testing only.

---

## 🎓 Project Info

- **Project Name**: IntelliPort — AI Powered Port Scanner
- **Level**: 4th Semester, Computer Science / IT
- **Domain**: Cybersecurity + Artificial Intelligence
- **Developer**: [Your Name]
- **Year**: 2025
