"""Require source-mapped feature coverage and rationale for present/planned groups."""

import argparse
import ast
from collections import Counter
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
CATALOG = "docs-site/reference/feature-groups.json"
RATIONALE = "docs-site/architecture/feature-rationale.mdx"
METHODS = "docs-site/reference/feature-methods.json"
METHODS_PAGE = "docs-site/architecture/feature-methods.mdx"


def source_columns(read):
    legacy = ast.parse(read("Controller/traffic_capture.py"))
    names = ("FLOW_COLUMNS", "DEVICE_COLUMNS", "NETWORK_COLUMNS", "ARP_COLUMNS", "LABEL_COLUMNS", "META_COLUMNS")
    constants = {target.id: ast.literal_eval(node.value) for node in legacy.body if isinstance(node, ast.Assign)
                 for target in node.targets if isinstance(target, ast.Name) and target.id in names}
    if set(constants) != set(names):
        raise ValueError("Legacy column definitions changed shape; update the catalog checker")
    old_columns = [value for name in names for value in constants[name]]
    home = ast.parse(read("Controller/home_sensor.py"))
    meta = next(ast.literal_eval(node.value) for node in home.body if isinstance(node, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == "META_COLUMNS" for t in node.targets))
    features = ast.parse(read("Controller/site_features.py"))
    cls = next(n for n in features.body if isinstance(n, ast.ClassDef) and n.name == "FeatureHistory")
    method = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == "features")
    definitions = [n for n in ast.walk(method) if isinstance(n, ast.Assign)
                   and any(isinstance(t, ast.Name) and t.id == "result" for t in n.targets)]
    if len(definitions) != 1 or not isinstance(definitions[0].value, ast.Call) or not isinstance(definitions[0].value.func, ast.Name) or definitions[0].value.func.id != "dict":
        raise ValueError("Site feature definition changed shape; update the catalog checker")
    keywords = definitions[0].value.keywords
    if any(k.arg is None for k in keywords):
        raise ValueError("Dynamic feature unpacking needs an explicit checker update")
    current = meta + [k.arg for k in keywords]
    return {"legacy": old_columns, "site_v3": current}


def validate(catalog, page, columns):
    if not isinstance(catalog,dict) or set(catalog) != {"version", "rationale_page", "groups"} or catalog["version"] != "feature-rationale-v1" or catalog["rationale_page"] != RATIONALE:
        raise ValueError("Invalid feature-rationale-v1 contract")
    groups = catalog["groups"]
    expected = {f"G{n}" for n in range(1,25)} | {"BASE", "DEVICE", "NETWORK", "LABELS", "QUALITY", "POLICY"}
    if not isinstance(groups, list) or any(not isinstance(g,dict) or not isinstance(g.get("id"),str) for g in groups) or Counter(g.get("id") for g in groups) != Counter(expected):
        raise ValueError("Expected each G1-G24 and six supporting groups exactly once")
    assigned = {"legacy": [], "site_v3": []}
    headings = [line[3:].strip() for line in page.splitlines() if line.startswith("## ")]
    for group in groups:
        if set(group) != {"id","title","status","model_use","legacy_columns","site_columns","rationale_heading"}:
            raise ValueError("Unknown or missing feature-group fields")
        if group["status"] not in ("legacy_lab","partial_site","supporting","audit_only","planned"):
            raise ValueError("Invalid group implementation status")
        if group["model_use"] not in ("requires_qualification","excluded","planned"):
            raise ValueError("Invalid model-use classification")
        heading = group["rationale_heading"]
        if headings.count(heading) != 1:
            raise ValueError("Missing/duplicate rationale heading for " + group["id"])
        section = page.split("## " + heading + "\n",1)[1].split("\n## ",1)[0]
        if len(section.split()) < 40:
            raise ValueError("Rationale section lacks a substantive explanation for " + group["id"])
        for schema, key in (("legacy","legacy_columns"),("site_v3","site_columns")):
            fields = group[key]
            if not isinstance(fields,list) or any(not isinstance(f,str) for f in fields):
                raise ValueError("Column mapping must contain text names")
            if group["status"] == "planned" and fields:
                raise ValueError("Planned groups cannot claim implemented columns")
            assigned[schema].extend(fields)
        if group["id"] in ("G10","LABELS") and group["model_use"] != "excluded":
            raise ValueError("Labels/audit metadata cannot silently become predictive inputs")
    for schema, names in columns.items():
        if Counter(assigned[schema]) != Counter(names) or any(n != 1 for n in Counter(names).values()):
            raise ValueError("Missing, duplicate or invented column assignments for " + schema)
    return {"valid": True, "groups": len(groups), "columns": {key:len(values) for key,values in columns.items()},
            "meaning": "Source names/status/rationale coverage only; mathematical definitions and detection value need review and independent experiments."}


def validate_methods(methods, page, catalog):
    """Require an authored recommendation for every schema-qualified column."""
    if (not isinstance(methods,dict) or set(methods) != {"version","research_date","page","sources","features","future_groups"}
            or methods["version"] != "feature-methods-v1" or methods["page"] != METHODS_PAGE):
        raise ValueError("Invalid feature method inventory")
    sources=methods["sources"]
    if (not isinstance(sources,dict) or not sources or any(not isinstance(v,dict) or set(v)!={"title","url"}
            or not isinstance(v["url"],str) or not v["url"].startswith("https://") for v in sources.values())):
        raise ValueError("Invalid method sources")
    expected={(schema,name):g["id"] for g in catalog["groups"]
              for schema,key in (("legacy","legacy_columns"),("site_v3","site_columns")) for name in g[key]}
    actual={}
    for feature in methods["features"]:
        if (not isinstance(feature,dict) or set(feature)!={"schema","name","group","units","recommended_measurement",
                "current_limit","qualification","references","recommendation_status"}):
            raise ValueError("Invalid method feature fields")
        key=(feature["schema"],feature["name"])
        if key in actual or expected.get(key)!=feature["group"]:
            raise ValueError("Missing, duplicate or misgrouped feature method")
        for field,minimum in (("units",1),("recommended_measurement",10),("current_limit",6),("qualification",6)):
            if not isinstance(feature[field],str) or len(feature[field].split())<minimum:
                raise ValueError("Feature method lacks substantive measurement/qualification")
        if (not feature["references"] or set(feature["references"])-set(sources)
                or feature["recommendation_status"]!="existing_measurement_requires_qualification_or_versioned_future_work"):
            raise ValueError("Method source/status mismatch")
        if "`"+feature["name"]+"`" not in page:
            raise ValueError("Method page omits a column")
        actual[key]=feature["group"]
    if actual!=expected:
        raise ValueError("Missing method inventory coverage")
    future=methods["future_groups"]
    if Counter(g["id"] for g in future)!=Counter(f"G{n}" for n in range(18,25)):
        raise ValueError("Planned method inventory must retain G18–G24")
    for group in catalog["groups"]:
        if "## "+group["id"]+":" not in page:
            raise ValueError("Method page omits a feature group")
    return len(actual)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--staged", action="store_true")
    args = parser.parse_args()
    def read(name):
        if args.staged:
            return subprocess.run(["git","show",":"+name],cwd=ROOT,check=True,capture_output=True).stdout.decode("utf-8")
        return (ROOT/name).read_text(encoding="utf-8")
    try:
        catalog=json.loads(read(CATALOG))
        result = validate(catalog,read(RATIONALE),source_columns(read))
        result["method_recommendations"]=validate_methods(json.loads(read(METHODS)),read(METHODS_PAGE),catalog)
    except (OSError,ValueError,TypeError,KeyError,StopIteration,SyntaxError,subprocess.CalledProcessError) as error:
        parser.exit(1,"Feature catalog check failed: "+str(error)+"\n")
    print(json.dumps(result,indent=2))


if __name__ == "__main__":
    main()
