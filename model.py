import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
import joblib

# Sample dataset
# Replace later with real phishing dataset

data = {
    'url_length': [20, 100, 50, 150, 30, 170],
    'has_https': [1, 0, 1, 0, 1, 0],
    'has_ip': [0, 1, 0, 1, 0, 1],
    'suspicious_words': [0, 1, 0, 1, 0, 1],
    'label': [0, 1, 0, 1, 0, 1]
}

# Create dataframe

df = pd.DataFrame(data)

X = df.drop('label', axis=1)
y = df['label']

# Split data

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42
)

# Train model

model = RandomForestClassifier()
model.fit(X_train, y_train)

# Save model

joblib.dump(model, 'phishing_model.pkl')

# Accuracy

predictions = model.predict(X_test)
print('Accuracy:', accuracy_score(y_test, predictions))