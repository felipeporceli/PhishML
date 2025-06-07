from flask import Flask, request, render_template, jsonify
from flask_cors import CORS
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.feature_selection import SelectPercentile, f_classif
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from xgboost import XGBClassifier
import matplotlib.pyplot as plt
import seaborn as sns
import os
from ModelHandller import Model, MakeInfrence
import tldextract


app = Flask(__name__)
CORS(app)  # Permite CORS para todas as rotas e origens

# Treinamento do modelo ao iniciar o servidor
data = pd.read_csv('phishing.csv')
data = data.drop('Index', axis=1)
data["class"] = data["class"].replace(-1, 0)

features = data.columns[0:-1]
target = data.columns[-1]
X = data[features]
y = data[target]

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

selector = SelectPercentile(percentile=60, score_func=f_classif)
selector.fit(X_train, y_train)
selected_features_idx = selector.get_support(indices=True)
selected_features = X.columns[selected_features_idx]

X = data[selected_features]
train_X, test_X, train_Y, test_Y = train_test_split(X, y, test_size=0.3, random_state=2)

clfs = [LogisticRegression(), DecisionTreeClassifier(), RandomForestClassifier(), SVC(), XGBClassifier()]
_, predictors = Model(clfs, train_X, train_Y, test_X, test_Y)

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    if request.method == 'POST':
        url = request.form['url']
        try:
            prediction = MakeInfrence(predictors, url)
            if prediction == 1:
                result = f"A URL \"{url}\" é considerada LEGÍTIMA."
            else:
                result = f"A URL \"{url}\" é considerada PHISHING."
        except Exception as e:
            result = f"Erro ao processar a URL: {str(e)}"
    return render_template('index.html', result=result)

@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json()
    url = data.get('url', '')
    try:
        prediction = MakeInfrence(predictors, url)
        return jsonify({'resultado': int(prediction)})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

if __name__ == '__main__':
    app.run(debug=True)

