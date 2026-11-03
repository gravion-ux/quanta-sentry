import argparse
import json
from pathlib import Path

from .inventory import inventory


def main():
    p=argparse.ArgumentParser(); p.add_argument("path",type=Path); p.add_argument("--output",type=Path); a=p.parse_args()
    rows=inventory(a.path); report={"standard_references":["FIPS 203","FIPS 204","FIPS 205"],"inventory":rows,
      "notice":"Inventory hints are not a compliance or quantum-safety determination."}
    out=json.dumps(report,indent=2)
    if a.output:a.output.write_text(out+"\n",encoding="utf-8")
    print(out)
if __name__=="__main__":main()
