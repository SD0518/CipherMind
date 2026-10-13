import pandas as pd

df = pd.read_csv(r"self_learn\nathan\BGL\BGL_2k.log_structured.csv")
df.drop("Label", axis=1, inplace=True)

df.to_json(r"self_learn\nathan\BGL\BGL_2k.log_structured.json", orient="records", indent=2)
