import pandas as pd, re, json
from bs4 import BeautifulSoup

def load_files():
    csv_file = 'juice_shop.csv'
    html_file = 'juice-shop.html'
    df = pd.read_csv(csv_file, engine='python', quotechar='"', on_bad_lines='skip')
    with open(html_file, 'r', encoding='utf-8', errors='ignore') as f:
        html_content = f.read()
    return df, html_content

def preprocess_endpoint(ep):
    ep = str(ep)
    # Remove method prefix
    ep = re.sub(r'^(GET|POST|PUT|DELETE|PATCH)\s+', '', ep)
    ep = re.sub(r'^https?://[^/]+', '', ep)
    ep = ep.split('?')[0]
    ep = re.sub(r'\{[^}]+\}', '', ep)
    return ep.rstrip('/')

def extract_zap_paths(html):
    soup = BeautifulSoup(html, 'html.parser')
    paths = set()
    for a in soup.find_all('a', href=True):
        href = a['href']
        if href.startswith('http') or href.startswith('/'):
            path = re.sub(r'^https?://[^/]+', '', href)
            paths.add(path)
    text = soup.get_text('\n')
    for match in re.findall(r'(https?://[^\s"\']+|/[^\s"\']+)', text):
        path = re.sub(r'^https?://[^/]+', '', match)
        paths.add(path)
    processed = set(p.split('#')[0] for p in paths)
    return processed

def match(df, zap_paths):
    tp=fp=fn=0
    matched_zap=set()
    for idx,row in df.iterrows():
        ep=preprocess_endpoint(row['Location (Endpoint)'])
        found=False
        for zp in zap_paths:
            if zp.startswith(ep):
                found=True
                matched_zap.add(zp)
                break
        if found:
            tp+=1
        else:
            fn+=1
    fp=len(zap_paths - matched_zap)
    return tp,fp,fn

def calc_metrics(tp,fp,fn):
    prec=tp/(tp+fp) if tp+fp>0 else 0
    rec=tp/(tp+fn) if tp+fn>0 else 0
    f1=2*prec*rec/(prec+rec) if prec+rec>0 else 0
    return prec,rec,f1

df,html=load_files()
zap_paths=extract_zap_paths(html)
TP,FP,FN=match(df,zap_paths)
precision,recall,f1=calc_metrics(TP,FP,FN)
print(json.dumps({'TP':TP,'FP':FP,'FN':FN,'precision':round(precision,3),'recall':round(recall,3),'f1':round(f1,3)}))