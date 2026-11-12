# threat_engine

Rule-based IaC scanner. Will contain:

- `parsers/terraform.py`   – HCL/Terraform AST parser
- `parsers/cloudformation.py` – CloudFormation YAML/JSON parser
- `rules/`                 – Individual security rule implementations
- `engine.py`              – Orchestrates parsers + rules → findings list

Not yet implemented.
