from sklearn.metrics import accuracy_score,precision_score,recall_score,r2_score,confusion_matrix,classification_report
from sklearn.ensemble import VotingClassifier
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
from FeatureExtractor import extract_features
from urllib.parse import urlparse
import Levenshtein
import tldextract
import re
import requests

api_key="AIzaSyA12yGY4e9N-GSbuTcDPsrZ_8oqMPLies0"

def plot_confusion_matrix(test_Y, predict_y):
    C = confusion_matrix(test_Y, predict_y)
    A =(((C.T)/(C.sum(axis=1))).T)
    B =(C/C.sum(axis=0))
    plt.figure(figsize=(20,4))
    labels = [1,2]
    cmap=sns.light_palette("blue")
    plt.subplot(1, 3, 1)
    sns.heatmap(C, annot=True, cmap=cmap, fmt=".3f", xticklabels=labels, yticklabels=labels)
    plt.xlabel('Predicted Class')
    plt.ylabel('Original Class')
    plt.title("Confusion matrix")
    plt.subplot(1, 3, 2)
    sns.heatmap(B, annot=True, cmap=cmap, fmt=".3f", xticklabels=labels, yticklabels=labels)
    plt.xlabel('Predicted Class')
    plt.ylabel('Original Class')
    plt.title("Precision matrix")
    plt.subplot(1, 3, 3)
    sns.heatmap(A, annot=True, cmap=cmap, fmt=".3f", xticklabels=labels, yticklabels=labels)
    plt.xlabel('Predicted Class')
    plt.ylabel('Original Class')
    plt.title("Recall matrix")
def Model(clfs,train_X,train_Y,test_X,test_Y):
    dic = thisdict = {
        "Model": [],
        "TrainAcc": [],
        "TestAcc": []
    }
    predictors = []
    for i in clfs:
        print(i.__class__.__name__)
        model = i.fit(train_X,train_Y)
        predictors.append(model)
        TrainPreds=model.predict(train_X)
        TestPreds=model.predict(test_X)
        TrainAcc = accuracy_score(train_Y,TrainPreds)
        print(f"TrainAcc: {TrainAcc}")
        TestAcc = accuracy_score(test_Y,TestPreds)
        print(f"TestAcc: {TestAcc}")
        print(classification_report(test_Y,TestPreds))
        plot_confusion_matrix(test_Y, TestPreds)
        dic["Model"]
        dic["Model"].append(i.__class__.__name__)
        dic["TrainAcc"].append(TrainAcc)
        dic["TestAcc"].append(TestAcc)
    estimators = []
    for i in predictors:
        estimators.append((i.__class__.__name__,i))
    EnsembleModel = VotingClassifier(estimators=estimators,weights=[3,1,1,2,1])
    print("EnsembleModel")
    model = EnsembleModel.fit(train_X,train_Y)
    predictors.append(model)
    TrainPreds=model.predict(train_X)
    TestPreds=model.predict(test_X)
    TrainAcc = accuracy_score(train_Y,TrainPreds)
    print(f"TrainAcc: {TrainAcc}")
    TestAcc = accuracy_score(test_Y,TestPreds)
    print(f"TestAcc: {TestAcc}")
    print(classification_report(test_Y,TestPreds))
    plot_confusion_matrix(test_Y, TestPreds)
    dic["Model"]
    dic["Model"].append("EnsembleModel")
    dic["TrainAcc"].append(TrainAcc)
    dic["TestAcc"].append(TestAcc)
    return dic, predictors

def is_possible_typosquatting(url, legit_domains):
    ext = tldextract.extract(url)
    subdomain = ext.subdomain.lower()
    domain = f"{ext.domain.lower()}.{ext.suffix.lower()}"
    path = urlparse(url).path.lower()

    # Quebrar subdomínio em partes
    sub_tokens = re.split(r'[.\-_]', subdomain) if subdomain else []
    path_tokens = re.findall(r'\w+', path) if path else []

    # Para debug
    print(f"[DEBUG] Domínio extraído: {domain}")
    print(f"[DEBUG] Subdomínio extraído: {sub_tokens}")
    print(f"[DEBUG] Caminho tokens: {path_tokens}")

    for legit in legit_domains:
        legit_ext = tldextract.extract(legit)
        legit_domain = f"{legit_ext.domain.lower()}.{legit_ext.suffix.lower()}"
        brand = legit_ext.domain.lower()

        print(f"[DEBUG] Verificando marca '{brand}' contra URL")

        # Se domínio oficial, ignora
        if domain == legit_domain:
            print("[DEBUG] Domínio legítimo confirmado, ignorando")
            continue

        # Se marca estiver no subdomínio (qualquer parte)
        if brand in sub_tokens:
            print(f"[DEBUG] Marca '{brand}' detectada no subdomínio")
            return True, legit

        # Se marca estiver no caminho
        if brand in path_tokens:
            print(f"[DEBUG] Marca '{brand}' detectada no caminho")
            return True, legit

    return False, None

def check_webrisk_google(url, api_key="AIzaSyA12yGY4e9N-GSbuTcDPsrZ_8oqMPLies0"):
    endpoint = "https://webrisk.googleapis.com/v1/uris:search"
    params = {
        "key": api_key,
        "uri": url,
        "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"]
    }

    try:
        response = requests.get(endpoint, params=params, timeout=5)
        response.raise_for_status()
        data = response.json()

        if "threat" in data:
            return -1  # URL maliciosa detectada
        else:
            return 1  # URL segura
    except requests.RequestException as e:
        print(f"[WebRisk] Erro ao consultar API: {e}")
        return 0  # Em caso de erro, assume como segura (ou você pode optar por 1)
    
def MakeInfrence(predictors, url):
    legit_domains = [
        "steamcommunity.com", "google.com", "facebook.com", "twitter.com", "linkedin.com",
        "youtube.com", "bradesco.com.br", "santander.com.br", "bb.com.br", "itau.com.br",
        "nubank.com.br", "iti.itau", "picpay.com", "caixa.gov.br", "next.me", "inter.co",
        "mercadopago.com.br", "pagbank.com.br", "willbank.com.br", "bancopan.com.br", "netflix.com", ""
    ]

    results = []  # Armazena os resultados de cada verificação

    # 1. Verificação de typosquatting
    typo, legit = is_possible_typosquatting(url, legit_domains)
    if typo:
        print(f"🚨 Phishing detectado: tentando se passar por {legit}")
        results.append(-1)
    else:
        print("✅ Typosquatting: URL parece legítima")
        results.append(1)

    # 2. Verificação via Google Web Risk API
    api_google = check_webrisk_google(url)
    if api_google == -1:
        print("🚨 Google Web Risk identificou URL maliciosa.")
        results.append(-1)
    elif api_google == 1:
        print("✅ Google Web Risk indicou URL segura.")
        results.append(1)
    else:
        print("⚠️ Google Web Risk não conseguiu determinar o status.")
        results.append(0)

    # 3. Verificação via modelo de machine learning
    try:
        features = extract_features(url)
        expected_columns = [
            'UsingIP', 'LongURL', 'ShortURL', 'PrefixSuffix-', 'SubDomains', 'HTTPS', 'DomainRegLen',
            'RequestURL', 'AnchorURL', 'LinksInScriptTags', 'ServerFormHandler', 'AbnormalURL',
            'AgeofDomain', 'DNSRecording', 'WebsiteTraffic', 'PageRank', 'GoogleIndex', 'StatsReport'
        ]
        if set(features.keys()) != set(expected_columns):
            print("❌ Erro: features ausentes ou incorretas")
            results.append(0)
        else:
            test = pd.DataFrame(features)
            prediction = predictors[5].predict(test)[0]
            prediction = int(prediction)
            print(f"🔍 Modelo de ML previu: {'Legítimo' if prediction == 1 else 'Phishing'}")
            results.append(prediction)
    except Exception as e:
        print(f"❌ Erro ao processar modelo de ML: {e}")
        results.append(0)

    # Voto majoritário pessimista: se qualquer verificação indicou -1, retorna -1
    print("\n======= RESULTADO FINAL =======")
    print(f"Votos das verificações: {results}")
    if -1 in results:
        print("🚨 Resultado final: PHISHING DETECTADO")
        return -1
    elif 0 in results:
        print("🚨 Resultado final: PHISHING DETECTADO")
        return -1
    else:
        print("✅ Resultado final: SITE LEGÍTIMO")
        return 1

