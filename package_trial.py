import os
import shutil
import zipfile
import re

# Paths
source_dir = r"c:\Users\chuck\redteam\onprem-test"
build_dir = r"c:\Users\chuck\redteam\onprem-trial"

# Clean build directory if exists
if os.path.exists(build_dir):
    shutil.rmtree(build_dir)

# Copy source
shutil.copytree(source_dir, build_dir)

# 1. Delete Next.js enterprise api routes
api_to_delete = [
    r"saas-dashboard\src\app\api\pyrit\config\route.ts",
    r"saas-dashboard\src\app\api\deepeval\config\route.ts",
    r"saas-dashboard\src\app\api\siem\config\route.ts"
]
for rel_path in api_to_delete:
    full_path = os.path.join(build_dir, rel_path)
    if os.path.exists(full_path):
        os.remove(full_path)
        print(f"Deleted: {rel_path}")

# 2. Modify page.tsx to set IS_TRIAL = true and hide UI elements
page_path = os.path.join(build_dir, r"saas-dashboard\src\app\page.tsx")
if os.path.exists(page_path):
    with open(page_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Prepend IS_TRIAL declaration inside Home() function
    content = content.replace(
        "export default function Home() {",
        "export default function Home() {\n  const IS_TRIAL = true;"
    )

    content = content.replace(
        "const IS_REDTEAM = false;",
        "const IS_REDTEAM = true;"
    )

    # Wrap PyRIT sidebar button in conditional rendering
    pyrit_btn_pattern = r"(<button\s+onClick=\{\(\)\s+=>\s+setActiveTab\(\"pyrit\"\)\}[\s\S]+?<\/button>)"
    content = re.sub(pyrit_btn_pattern, r"{!IS_TRIAL && (\1)}", content)

    # Wrap DeepEval sidebar button in conditional rendering
    deepeval_btn_pattern = r"(<button\s+onClick=\{\(\)\s+=>\s+setActiveTab\(\"deepeval\"\)\}[\s\S]+?<\/button>)"
    content = re.sub(deepeval_btn_pattern, r"{!IS_TRIAL && (\1)}", content)

    # Wrap PyRIT checkbox block in conditional rendering
    content = content.replace(
        "{/* PyRIT */}\n                          <div className=\"space-y-2\">",
        "{/* PyRIT */}\n                          {!IS_TRIAL && (\n                          <div className=\"space-y-2\">"
    )
    content = content.replace(
        "Multi-turn Fuzzing 🔄</span>\n                              </label>\n                            </div>\n                          </div>",
        "Multi-turn Fuzzing 🔄</span>\n                              </label>\n                            </div>\n                          </div>\n                          )}"
    )

    # Wrap DeepEval checkbox block in conditional rendering
    content = content.replace(
        "{/* DeepEval */}\n                          <div className=\"space-y-2\">",
        "{/* DeepEval */}\n                          {!IS_TRIAL && (\n                          <div className=\"space-y-2\">"
    )
    content = content.replace(
        "LLM-as-a-Judge Evaluation ⚖️</span>\n                              </label>\n                            </div>\n                          </div>",
        "LLM-as-a-Judge Evaluation ⚖️</span>\n                              </label>\n                            </div>\n                          </div>\n                          )}"
    )

    # Hide Splunk option in SIEM configuration
    content = content.replace(
        '<option value="splunk">Splunk (HEC)</option>',
        '{!IS_TRIAL && <option value="splunk">Splunk (HEC)</option>}'
    )

    with open(page_path, "w", encoding="utf-8") as f:
        f.write(content)
    print("Modified page.tsx for Trial Mode UI.")

    # 2b. Modify docker-compose.yml to change THREAT suffix to REDTEAM suffix and isolate image tags
    compose_path = os.path.join(build_dir, "docker-compose.yml")
    if os.path.exists(compose_path):
        with open(compose_path, "r", encoding="utf-8") as f:
            compose_content = f.read()
        compose_content = compose_content.replace("-THREAT", "-REDTEAM").replace("G1163RT-THREAT", "G1163RT-REDTEAM")
        compose_content = compose_content.replace("-threat:latest", "-redteam:latest")
        compose_content = compose_content.replace('"3001:3000"', '"3000:3000"')
        compose_content = compose_content.replace('"8086:8080"', '"8085:8080"')
        compose_content = compose_content.replace('"5008:5005"', '"5007:5005"')
        compose_content = compose_content.replace("image: g1163rt-onprem-saas-dashboard:latest", "image: g1163rt-onprem-saas-dashboard-redteam:latest")
        compose_content = compose_content.replace("image: g1163rt-onprem-runner:latest", "image: g1163rt-onprem-runner-redteam:latest")
        with open(compose_path, "w", encoding="utf-8") as f:
            f.write(compose_content)
        print("Modified docker-compose.yml for RedTeam suffixes and isolated image tags.")

# 3. Prune scanners.py
scanners_path = os.path.join(build_dir, r"agent-code\scanners.py")
if os.path.exists(scanners_path):
    with open(scanners_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    pruned_lines = []
    skip_mode = False
    for line in lines:
        if "import pyrit" in line or "import deepeval" in line:
            # Skip actual imports
            continue
        if "def run_actual_pyrit_scan" in line or "def run_actual_deepeval_evaluation" in line or "def simulate_pyrit_scan" in line or "def simulate_deepeval_evaluation" in line:
            skip_mode = True
            # Write a stub function
            func_name = line.split("def ")[1].split("(")[0]
            pruned_lines.append(f"def {func_name}(*args, **kwargs):\n    logger.warning('{func_name} disabled in free trial.')\n    return []\n\n")
            continue
        if skip_mode:
            # We skip lines until we see a new top-level function or definition starting with "def " or "class "
            if line.startswith("def ") or line.startswith("class ") or line.strip() == "":
                if not line.strip() == "":
                    skip_mode = False
                    pruned_lines.append(line)
            continue
        pruned_lines.append(line)

    # Force HAS flags to False
    scanners_code = "".join(pruned_lines)
    scanners_code = scanners_code.replace("HAS_PYRIT = True", "HAS_PYRIT = False")
    scanners_code = scanners_code.replace("HAS_DEEPEVAL = True", "HAS_DEEPEVAL = False")

    with open(scanners_path, "w", encoding="utf-8") as f:
        f.write(scanners_code)
    print("Pruned scanners.py of PyRIT and DeepEval.")

# 4. Zip the bundle
zip_paths = [
    r"c:\Users\chuck\redteam\public-dist\g1163rt-redteam-trial.zip",
    r"c:\Users\chuck\redteam\saas-dashboard\public\g1163rt-redteam-trial.zip",
    r"c:\Users\chuck\G1163RT-G3 Threat Aggregator\customer_portal\Public\redteam\g1163rt-redteam-trial.zip"
]

def make_zip(out_zip):
    parent = os.path.dirname(out_zip)
    if not os.path.exists(parent):
        os.makedirs(parent, exist_ok=True)
    with zipfile.ZipFile(out_zip, "w", zipfile.ZIP_DEFLATED) as z:
        for root, dirs, files in os.walk(build_dir):
            # Prune directories to skip packaging node_modules, .next, and git/cache/venv repos
            dirs[:] = [d for d in dirs if d not in ('node_modules', '.next', '.git', '.pytest_cache', '__pycache__', '.venv')]
            for file in files:
                fpath = os.path.join(root, file)
                relpath = os.path.relpath(fpath, build_dir)
                z.write(fpath, relpath)
    print(f"Created ZIP bundle: {out_zip}")

for path in zip_paths:
    make_zip(path)

print("Trial packaging build completed successfully. Permanent directory: onprem-trial")
