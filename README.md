# XSS Optimizer

XSS Optimizer is a **Burp Suite extension** designed to automatically identify and exploit potential Cross-Site Scripting (XSS) vectors. It leverages a **Genetic Algorithm (GA)** to adaptively refine payloads and bypass filters in real time, accelerating the discovery of complex or partially filtered injection points.

---

## Table of Contents

1. [Overview](#overview)
2. [Features](#features)
3. [Requirements](#requirements)
4. [Installation](#installation)
5. [Usage](#usage)
6. [How It Works](#how-it-works)
   - [Architecture](#architecture)
   - [Genetic-Algorithm Core](#genetic-algorithm-core)
   - [Key Components](#key-components)
7. [Configuration](#configuration)
8. [Logs and Persistence](#logs-and-persistence)
9. [Advanced Topics](#advanced-topics)
10. [Known Limitations](#known-limitations)
11. [FAQ](#faq)
12. [License](#license)

---

## Overview

**XSS Optimizer** extends Burp Suite's capabilities by introducing a **GA-driven** approach to testing web parameters for XSS vulnerabilities. Instead of relying on a static list of payloads, it generates and mutates payloads over multiple “generations,” using feedback from the application’s responses to converge on more effective injection vectors.

Key highlights:

- Automates fuzzing and bypass attempts for XSS.
- Integrates seamlessly with **Burp Suite**.
- Stores logs for each attempt, providing a thorough record of injection attempts.
- Maintains a JSON-based “effectiveness score” for each (URL, technique) pair, allowing incremental learning.

---

## Features

- **Automated XSS Discovery**: Injects payloads across GET/POST parameters, searching for both reflected and stored XSS.
- **Genetic Algorithm Engine**:
  - Evolves payloads over multiple generations.
  - Rewards partial successes or reflections in the response.
  - Applies different encoding/obfuscation “techniques.”
- **GUI Integration**:
  - Dedicated “XSS Optimizer” tab in Burp Suite.
  - Right-click menu item: “Send to XSS Optimizer.”
- **Result Tracking**:
  - Writes attempts to a CSV file (`xss_optimizer.csv`).
  - Maintains a `tech_eff.json` to store which technique has historically worked on a given URL.

---

## Requirements

- **Burp Suite** 2.x (or newer), either Community or Professional Edition.
- **Java 8+** (Recommended) on the system where Burp is running.
- **Jython** (if using a Python-based approach) or the plugin compiled as a JAR (Java) for easy loading in Burp.

---

## Installation

1. **Obtain the Extension**  
   - Download or clone the repository containing the XSS Optimizer code.
   - If distributed as a `.py` file (e.g., `XSSOptimizer-1.0.py`), ensure you have it locally.

2. **Load into Burp Suite**  
   - In Burp, navigate to **Extender** > **Extensions** > **Add**.
   - **Extension Type**: python (if `.py`).
   - **Extension File**: select the path to `XSSOptimizer-1.0.py`.
   - Burp should confirm successful loading: “XSS Optimizer loaded.”

3. **Verify**  
   - A new tab labeled  “XSS Optimizer” should appear in Burp Suite’s top menu.
   - Any load-time messages will appear in the **Extender** console.

---

## Usage

1. **Capturing Requests**  
   - (Optional) In the “XSS Optimizer” tab, check **Proxy Capture** if you want every new Proxy request with parameters to be queued automatically.
   - Alternatively, right-click on any HTTP request in Burp (e.g., Proxy history, Target, Repeater) and choose **“Send to XSS Optimizer”**.

2. **Managing the Table**  
   - Each parameter is listed as a row in the XSS Optimizer tab:
     - **URL**: The request’s URL.
     - **Method**: GET or POST.
     - **Param**: The real parameter name=value extracted.
     - **Payload**: Once the GA is running, it shows the best (current) payload for that row.
     - **Code**: Latest HTTP status code from injection attempts.
     - **Result**: e.g., “exploitable” or “no explotable,” indicating the GA’s final assessment.

3. **Starting the GA**  
   - **Auto-Optimize**: If enabled, newly added rows are automatically tested.
   - Or select a row and click **“Optimize Selected”**. The GA then runs in the background, updating the table.

4. **Observing Outputs**  
   - The table updates in real time: if the GA finds an exploit, the row’s Result changes to “exploitable.”
   - Detailed logs go to the CSV file. The plugin also updates its JSON-based effectiveness record.

---

## How It Works

### Architecture

1. **Burp Suite Integration**: Hooks into Proxy events, context menus, Repeater, etc.  
2. **XSS Optimizer Core**: The Genetic Algorithm that orchestrates payload generation, selection, crossover, and mutation.  
3. **Request/Response Manager**: Injects the GA’s chosen payload, sends it, analyzes the final response.  
4. **Persistence**: Writes to `xss_optimizer.csv`, updates `tech_eff.json`.

### Genetic-Algorithm Core

- **Population**: Each individual is `(base_payload_index, technique_index, length_value)`.
- **Evaluation** (Fitness):
  - Infill a random ID, apply chosen technique (e.g., `urlEncode`, `polyglot`).
  - Inject into request parameter, send, parse response.
  - Score = 10 if fully exploitable, lower if partial reflection or error.
  - Historical “bonus” if that technique previously succeeded on that URL.
- **Selection + Reproduction**:
  - Sort by fitness, pick top survivors.
  - **Crossover** merges gene segments from two parents.  
  - **Mutation** randomly changes one gene (new technique, new payload index, new length).
- **Iterate** until exploit or max attempts.

### Key Components

- **`evaluate_xss()`**: Builds the mutated payload, updates the request parameter, sends it, and calculates a score based on reflection or script execution.  
- **`optimize_task()`**: Orchestrates the GA loop in a background thread, repeatedly refining the population’s individuals over multiple generations.

---

## Configuration

- **Proxy Capture**: Toggles whether new Proxy requests are queued automatically.
- **Auto-Optimize**: Runs the GA on newly added rows without manual clicks.
- **(Advanced)**: Modify the plugin’s source to change the population size, generations, or expand `COMMON_PAYLOADS` / `TECHNIQUES`.

---

## Logs and Persistence

1. **`xss_optimizer.csv`**:  
   - Each row has `ID,URL,Param,Method,Status,Result,Payload`.  
   - Written every time the plugin sends an injection attempt.

2. **`tech_eff.json`**:  
   - Stores `(URL##Technique) : bonusScore` to reward repeated success of a technique on the same domain or path.

---

## Advanced Topics

- **Context-Aware**: Potentially modify the plugin to detect whether injection is in HTML text vs attribute vs. JS context.
- **Scaling**: GA can generate numerous requests. Consider rate-limits or WAF interactions.
- **Combining ML**: Pair the GA approach with a classifier to guess best technique given certain response patterns, reducing generational cycles.

---

## Known Limitations

1. **High Request Count**: The GA must evaluate multiple individuals each generation, possibly leading to large request volumes.
2. **Not Fully Context-Aware**: By default, it uses a broad set of payloads, which might not always match the injection context precisely.
3. **Session Management**: The plugin reuses Burp’s session/cookies, but if the application has heavy CSRF measures or reauth requirements, more manual steps may be needed.
4. **Partial**: Focuses mainly on XSS. Extending to other injection classes (SQLi, Command Injection) would require new logic and payload sets.

---

## FAQ

**Q1**: *Why am I not finding exploits on a known vulnerable page?*  
**A**: Ensure the parameter truly is vulnerable and that you have “Auto-Optimize” or manual “Optimize Selected” in operation. Also verify you have enough GA attempts (pop size, generation count).

**Q2**: *Does it handle multi-parameter body?*  
**A**: Yes. Each parameter is typically listed as a separate row. The GA runs for each row individually.

**Q3**: *Can I add custom payloads?*  
**A**: Yes, edit the `COMMON_PAYLOADS` array in the source code to incorporate new or more advanced payloads.

**Q4**: *Is this plugin free/open source?*  
**A**: Yes, licensed under an open license (see below). Feel free to fork and extend it.

---

## License

XSS Optimizer is distributed under the [MIT License](https://opensource.org/licenses/MIT). Refer to the `LICENSE` file in this repository for details.

--- 

**Thank you for using XSS Optimizer!** 

If you have suggestions or would like to contribute, please open an issue or submit a pull request on GitHub.

