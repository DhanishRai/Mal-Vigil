import os
import numpy as np
import lightgbm as lgb
from sklearn.model_selection import train_test_split

os.makedirs("models", exist_ok=True)

# Generate synthetic baseline reflecting clean vs packed/malware distributions
# Features: [num_sections, max_entropy, mean_entropy, has_rwe, susp_api_count, total_imports, size_ratio]
np.random.seed(42)
n_samples = 3000

# Benign samples: normal entropy (4-6.5), few/no RWE sections, standard APIs
benign = np.column_stack([
    np.random.randint(3, 7, n_samples),
    np.random.uniform(4.0, 6.4, n_samples),
    np.random.uniform(3.0, 5.5, n_samples),
    np.zeros(n_samples),
    np.random.randint(0, 2, n_samples),
    np.random.randint(40, 200, n_samples),
    np.random.uniform(0.9, 1.2, n_samples)
])

# Malicious samples: high entropy (7.2-8.0), RWE sections present, injection APIs, large virtual deltas
malicious = np.column_stack([
    np.random.randint(1, 9, n_samples),
    np.random.uniform(7.1, 7.99, n_samples),
    np.random.uniform(6.5, 7.8, n_samples),
    np.random.choice([0, 1], size=n_samples, p=[0.2, 0.8]),
    np.random.randint(2, 6, n_samples),
    np.random.randint(5, 50, n_samples),
    np.random.uniform(1.5, 4.0, n_samples)
])

X = np.vstack([benign, malicious])
y = np.array([0] * n_samples + [1] * n_samples)

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.15, random_state=42)

model = lgb.LGBMClassifier(
    n_estimators=100,
    learning_rate=0.05,
    max_depth=5,
    num_leaves=31,
    random_state=42
)
model.fit(X_train, y_train)

# Save the trained model to text
model_path = os.path.join("models", "malware_lgbm.txt")
model.booster_.save_model(model_path)
print(f"Model saved successfully to {model_path}")