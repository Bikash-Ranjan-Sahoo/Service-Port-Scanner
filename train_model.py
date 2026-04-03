# ============================================================
# IntelliPort - AI Model Trainer
# File: train_model.py
# Purpose: Train a Random Forest model to predict port risk
# Run this ONCE before starting the main application
# ============================================================

# --- Import Libraries ---
import pandas as pd                        # For reading CSV data
from sklearn.ensemble import RandomForestClassifier  # Our AI algorithm
from sklearn.model_selection import train_test_split # Split data for testing
from sklearn.preprocessing import LabelEncoder       # Convert text to numbers
from sklearn.metrics import accuracy_score           # Check how accurate our AI is
import pickle                              # Save the trained model to a file
import os

print("=" * 50)
print("  IntelliPort - AI Model Training")
print("=" * 50)

# -------------------------------------------------------
# STEP 1: Load the Dataset
# -------------------------------------------------------
print("\n[1/5] Loading dataset...")

# Read the CSV file that contains port data and risk labels
df = pd.read_csv("intelliport_dataset.csv")

print(f"      Loaded {len(df)} records from dataset.")
print(f"      Columns: {list(df.columns)}")

# -------------------------------------------------------
# STEP 2: Convert Text Columns to Numbers
# AI cannot understand text like "TCP" or "open"
# We must convert them to numbers like 0, 1, 2
# -------------------------------------------------------
print("\n[2/5] Encoding text data to numbers...")

# Create encoders for each text column
protocol_encoder = LabelEncoder()
status_encoder   = LabelEncoder()

# Fit and transform the columns
df["protocol_enc"] = protocol_encoder.fit_transform(df["protocol"])
df["status_enc"]   = status_encoder.fit_transform(df["status"])

print("      'TCP/UDP' → numbers ✓")
print("      'open/closed/filtered' → numbers ✓")

# -------------------------------------------------------
# STEP 3: Prepare Features (inputs) and Labels (output)
# Features = what the AI looks at
# Label    = what the AI should predict (risk_level)
# -------------------------------------------------------
print("\n[3/5] Preparing features and labels...")

# X = input features (port, protocol, status)
X = df[["port", "protocol_enc", "status_enc"]]

# y = output label (0=Safe, 1=Suspicious, 2=Dangerous)
y = df["risk_level"]

print("      Input features: port, protocol, status")
print("      Output label: risk_level (0=Safe, 1=Suspicious, 2=Dangerous)")

# -------------------------------------------------------
# STEP 4: Train the AI Model
# We split data: 80% for training, 20% for testing
# -------------------------------------------------------
print("\n[4/5] Training Random Forest AI model...")

# Split the data
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# Create and train the Random Forest model
# n_estimators=100 means 100 decision trees working together
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Check accuracy on test data
y_pred    = model.predict(X_test)
accuracy  = accuracy_score(y_test, y_pred)

print(f"      Model trained successfully!")
print(f"      Accuracy: {accuracy * 100:.1f}%")

# -------------------------------------------------------
# STEP 5: Save the Model and Encoders to Files
# These files will be loaded by the main application
# -------------------------------------------------------
print("\n[5/5] Saving model and encoders...")

# Save the trained model
with open("intelliport_model.pkl", "wb") as f:
    pickle.dump(model, f)

# Save the encoders (needed to encode new inputs during scanning)
with open("intelliport_encoders.pkl", "wb") as f:
    pickle.dump({
        "protocol": protocol_encoder,
        "status":   status_encoder
    }, f)

print("      Saved: intelliport_model.pkl")
print("      Saved: intelliport_encoders.pkl")

print("\n" + "=" * 50)
print("  ✅ Training Complete! You can now run:")
print("     python intelliport_gui.py")
print("=" * 50)
