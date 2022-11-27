import json

with open('test.json') as f:
    jsn = json.load(f)

for jsn_key in jsn:
    print(jsn_key)

for jsn_val in jsn.values():
    print(jsn_val)

print(jsn_val["City"])
