import pandas as pd
import urllib.parse
import html
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
import joblib

def decode_payload(payload):
    if not isinstance(payload, str):
        return ""
    decoded_url = urllib.parse.unquote(payload)
    decoded_html = html.unescape(decoded_url)
    return decoded_html.lower()

print("Loading dataset...")
df = pd.read_csv("data/XSS_Dataset.csv")
df = df.dropna()

# ==========================================
# 1.5 UPGRADE: ADVERSARIAL DATA AUGMENTATION
# ==========================================
print("Injecting Adversarial Benign Data to fix Dataset Bias...")
adversarial_sentences = [
    "I am writing a script today to show an alert on my screen.",
    "The doctor gave me a new medical script.",
    "Did you get the weather alert on your phone?",
    "I love baking chocolate chip cookies.",
    "My favorite programming language is javascript.",
    "Please clear your browser cookie history.",
    "The movie script was well written and directed.",
    "Alert! The server is down for maintenance.",
    "On error, please restart the application.",
    "She has a beautiful handwriting script."
] * 10 # Multiply by 10 to give these examples enough mathematical weight

# Create a mini dataframe of our custom safe data (Label = 0)
adv_df = pd.DataFrame({
    'Sentence': adversarial_sentences,
    'Label': [0] * len(adversarial_sentences)
})

# Merge it into the main dataset
df = pd.concat([df, adv_df], ignore_index=True)
# ==========================================

print("Decoding and cleaning payloads...")
df['Cleaned_Sentence'] = df['Sentence'].apply(decode_payload)

X = df['Cleaned_Sentence']
y = df['Label']

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# We use both words and characters now to understand context better
print("Converting text to Features...")
vectorizer = TfidfVectorizer(analyzer='word', ngram_range=(1, 3), max_features=5000)
X_train_vectorized = vectorizer.fit_transform(X_train)
X_test_vectorized = vectorizer.transform(X_test)

print("Training the AI...")
model = RandomForestClassifier(
    n_estimators=100, 
    max_depth=35,             
    min_samples_split=5,      
    random_state=42, 
    n_jobs=-1
)

model.fit(X_train_vectorized, y_train)
predictions = model.predict(X_test_vectorized)

accuracy = accuracy_score(y_test, predictions)
print("======================================")
print(f"Final Test Accuracy: {accuracy * 100:.2f}%")
print("======================================\n")

print("Detailed Security Analysis (Precision & Recall):")
print(classification_report(y_test, predictions))

joblib.dump(model, "xss_model_rf.pkl")
joblib.dump(vectorizer, "vectorizer_rf.pkl")
print("\nAdversarial-Resistant Model successfully saved!")