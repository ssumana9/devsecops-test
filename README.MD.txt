 🚀 Vulnerability Prioritization System

This project is a **Vulnerability Prioritization System** that helps organizations process vulnerability data and rank them based on severity, source, and fix availability. The script processes CSV vulnerability data and applies a **custom prioritization algorithm** to provide actionable insights.

---

## Setup Instructions**
### Prerequisites**
Ensure you have the following installed:
- **Git** → Install from https://github.com/
- **Python (3.x)** → Install from [python.org](https://www.python.org/downloads/)
- **pip** → Should be installed with Python (verify with `pip --version`)

### Clone the Repository**
git clone https://github.com/ssumana9/devsecops-test
cd devsecops-test
Install Dependencies
Run the following command to install required Python libraries:

pip install pandas flask argparse matplotlib
Run the Script
python vuln.py
Usage Examples

Run with Default Prioritization Weights
python vuln.py
Run with Custom Weights
You can customize the weights for severity, source, and fix availability:

python vuln.py --severity_weight 12 --source_weight 6 --fix_weight 4
Access API Endpoint
After running the script, you can query results using:
arduino
http://127.0.0.1:5000/get_vulnerabilities
Explanation of the Prioritization Algorithm
This script prioritizes vulnerabilities based on CVSS scores, severity, audit due dates, source, and fix availability.

🎯 Priority Score Calculation
Each vulnerability is assigned a priority score using the following weighted factors:

Factor	Contribution (%)	Explanation
CVSS Score	40%	Higher scores indicate more severe vulnerabilities.
Time Until Audit	25%	Less time = higher priority.
Severity Level	20%	Critical > High > Medium > Low.
Source Weight	10%	AWS > GitHub (due to infrastructure risk).
Fix Availability	5%	If no fix is available, priority increases.
🎯 Severity Classification (Based on NIST)
The severity is assigned based on the CVSS (Common Vulnerability Scoring System) score as per NIST guidelines:

Low: 0.1 - 3.9
Medium: 4.0 - 6.9
High: 7.0 - 8.9
Critical: 9.0 - 10.0
📌 Assumptions
CVSS scores determine severity

Severity classification follows NIST (National Institute of Standards and Technology) guidelines.
AWS vulnerabilities are more critical than GitHub

AWS (Weight: 5) → Security misconfigurations in cloud environments pose greater risks to business operations.
GitHub (Weight: 3) → Vulnerabilities impact code but have mitigations like access control.
Fix availability impacts priority

If a fix is available, the vulnerability receives a lower priority.
If a fix is NOT available, priority is increased.
Audit due date matters
Vulnerabilities with closer audit deadlines get higher priority.
📌 Outputs
Prioritized CSV File → prioritized_vulnerabilities.csv
JSON Output for API → prioritized_vulnerabilities.json
Severity Bar Chart → severity_chart.png
API Endpoint → http://127.0.0.1:5000/get_vulnerabilities

📌 Author
Your Name
Email: sumana@violetx.com
GitHub: ssumana9