# Evaluation harness stub (simplified)
import spacy, json
from sklearn.metrics import classification_report

def main(model, gold, out_dir="artifacts"):
    nlp = spacy.load(model)
    records = [json.loads(l) for l in open(gold)]
    y_true,y_pred=[],[]
    for r in records:
        doc=nlp(r["text"])
        pred=[e.label_ for e in doc.ents]
        gold=[e["label"] for e in r["entities"]]
        y_true.extend(gold); y_pred.extend(pred if pred else ["NONE"])
    report=classification_report(y_true,y_pred,output_dict=True)
    with open(f"{out_dir}/metrics.json","w") as f: json.dump(report,f,indent=2)

if __name__=="__main__":
    import argparse,os
    ap=argparse.ArgumentParser()
    ap.add_argument("--model",required=True)
    ap.add_argument("--gold",required=True)
    ap.add_argument("--out_dir",default="artifacts")
    args=ap.parse_args()
    os.makedirs(args.out_dir,exist_ok=True)
    main(args.model,args.gold,args.out_dir)
