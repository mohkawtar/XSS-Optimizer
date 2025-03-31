XSS Optimizer
=============

XSS Optimizer is a **Burp Suite extension** that integrates with your pentesting workflow to automatically identify and exploit potential XSS vectors. It employs a **Genetic Algorithm (GA)** to adaptively generate and refine payloads and bypasses for different injection contexts.

Table of Contents
-----------------

1.  [Features](#features)
    
2.  [Requirements](#requirements)
    
3.  [Installation](#installation)
    
4.  [Usage](#usage)
    
5.  [How It Works](#how-it-works)
    
    *   [Architecture Overview](#architecture-overview)
        
    *   [Genetic Algorithm Core](#genetic-algorithm-core)
        
    *   [Key Components](#key-components)
        
6.  [Configuration](#configuration)
    
7.  [Results and Logs](#results-and-logs)
    
8.  [Advanced Topics](#advanced-topics)
    
9.  [Limitations and Known Issues](#limitations-and-known-issues)
    
10.  [FAQ](#faq)
    
11.  [License](#license)
    

Features
--------

*   **Automated XSS Discovery**: Finds reflected and stored XSS across GET/POST parameters by injecting evolutionary-generated payloads.
    
*   **Genetic Algorithm Engine**: Adapts and improves payloads based on partial or full injection success.
    
*   **Context-Aware Placeholder** ∗optional∗\*optional\*∗optional∗: Potential to recognize HTML vs. attribute contexts.
    
*   **Integration with Burp Suite**: Captures requests in real time, populates a table with parameters, and allows sending them to XSS Optimizer.
    
*   **Logs and Persistence**:
    
    *   Writes a CSV (xss\_optimizer.csv) for each tested vector.
        
    *   Maintains a JSON-based effectiveness record (tech\_eff.json) to reward techniques that worked historically on specific URLs.
        

Requirements
------------

*   **Burp Suite** (Professional or Community Edition) 2.x (or later).
    
*   **Jython** or **Python** environment if needed by Burp (depending on how you load the plugin, Java-based or Jython-based).
    
*   A recent version of **Java** (8+ recommended).
    

Installation
------------

1.  **Download the Extension**
    
    *   You can clone this repository or download the plugin .py file (e.g., XSSOptimizer-1.0.py).
        
2.  **Load Extension in Burp Suite**
    
    *   Launch Burp Suite.
        
    *   Go to **Extender** -> **Extensions** -> **Add**.
        
    *   Under Extension details:
        
        *   **Extension Type**: python
            
        *   **Extension File**: Select XSSOptimizer-1.0.py
            
    *   Wait for Burp Suite to load the extension. You should see a message: XSS Optimizer loaded successfully.
        
3.  **Verify Installation**
    
    *   A new tab named **XSS Optimizer** should appear at the top of Burp’s main interface.
        
    *   In the **Extender** -> **Extensions** tab, you should see the status: Loaded.
        

Usage
-----

1.  **Enable Proxy Capture (Optional)**
    
    *   In the XSS Optimizer tab, you can check “Proxy Capture” to automatically add new requests with parameters whenever Burp Proxy sees them.
        
2.  **Send Requests Manually**
    
    *   Within Burp (e.g., Proxy history, Target site map, Repeater), you can right-click a request -> **Send to XSS Optimizer**.
        
    *   The selected request(s) will appear in the plugin’s table, each parameter as a separate row.
        
3.  **Auto-Optimize / Manual Optimize**
    
    *   **Auto-Optimize**: Check the box in the plugin’s interface. The engine will automatically begin a Genetic Algorithm search for XSS vectors on new or pending items.
        
    *   **Optimize Selected**: Click the button in the plugin tab after selecting a row in the table to run the GA only for that row.
        
4.  **Monitor Results**
    
    *   The table displays columns: **URL**, **Method**, **Param** (name=value), **Payload**, **Code**, **Result**.
        
    *   When a GA run completes or finds an exploit, the row updates to **Result = exploitable**.
        
5.  **Review Logs**
    
    *   Check xss\_optimizer.csv for appended lines about each injection attempt.
        
    *   The plugin uses tech\_eff.json internally to store the “bonus” for techniques that previously worked, so you do not need to edit it manually.
        

How It Works
------------

### Architecture Overview

Plain textANTLR4BashCC#CSSCoffeeScriptCMakeDartDjangoDockerEJSErlangGitGoGraphQLGroovyHTMLJavaJavaScriptJSONJSXKotlinLaTeXLessLuaMakefileMarkdownMATLABMarkupObjective-CPerlPHPPowerShell.propertiesProtocol BuffersPythonRRubySass (Sass)Sass (Scss)SchemeSQLShellSwiftSVGTSXTypeScriptWebAssemblyYAMLXML`   diffCopiar+-----------------------------+  +--------------------------+  |  Burp Suite Integration     |  |  Genetic Algorithm Core  |  |  (Extender, Proxy, UI)      |  |  (Population, Eval, ...) |  +-----------+-----------------+  +------------+-------------+              |                                |              v                                v  +---------------------------+     +---------------------------+  |    Request/Response Mgr   |     |    Persistence/Logs      |  |  (Inject, send, parse)    |     |  (CSV, JSON for bonus)   |  +---------------------------+     +---------------------------+   `

1.  **Burp Suite Integration**: Hooks into Proxy, Repeater, and right-click menus to gather requests.
    
2.  **Request/Response Manager**: Takes a base request, injects payloads, sends them, and analyzes the final response code and body.
    
3.  **Genetic Algorithm Core**: Builds a population of (payload\_base, technique, length\_val), evolves them, checks success in partial or full injection.
    
4.  **Persistence**: Logs all attempts in CSV, stores technique effectiveness in JSON.
    

### Genetic Algorithm Core

*   **Population**: Each individual is a (base\_payload\_idx, technique\_idx, length\_val).
    
*   **Fitness**: Higher if the plugin finds unique\_id reflected, or if the response code = 200 with script execution. A bonus is added if technique historically succeeded on that URL.
    
*   **Selection**: Sort by fitness, pick top k for “breeding.”
    
*   **Crossover**: For each gene, randomly inherit from father or mother.
    
*   **Mutation**: Randomly alter (base\_payload\_idx, technique\_idx, length\_val) with a small probability.
    
*   **Iteration**: Repeat for a number of generations or until an exploitable XSS is found.
    

### Key Components

*   **evaluate\_xss()**: Builds the mutated payload, updates the parameter in the request, sends it, and scores the result.
    
*   **optimize\_task()**: The GA process that runs in a background thread, controlling the generational loop.
    

Configuration
-------------

You can configure various parts in the **XSS Optimizer** tab within Burp:

*   **Proxy Capture**: Toggle whether to automatically add new requests from the Proxy.
    
*   **Auto-Optimize**: Run the GA automatically on new parameters without manual clicks.
    
*   **(Advanced)** Modify the plugin’s source code to tweak COMMON\_PAYLOADS, TECHNIQUES, or the GA parameters (pop\_size, generations, mutation rate, etc.).
    

Results and Logs
----------------

1.  **Table Columns** in XSS Optimizer tab:
    
    *   **URL**: Full or partial URL.
        
    *   **Method**: GET/POST.
        
    *   **Param**: Name=Value extracted from the request.
        
    *   **Payload**: The latest GA-chosen payload with the highest score.
        
    *   **Code**: HTTP status code from the best attempt.
        
    *   **Result**: “exploitable” / “no explotable” / “pendiente” / etc.
        
2.  **CSV File** (xss\_optimizer.csv):
    
    *   Appends a line each time an injection is tested:
        
        *   ID,URL,Param,Method,Status,Result,Payload
            
3.  **tech\_eff.json**:
    
    *   jsonCopiar{ "http://example.com##url": 3, "http://example.com##polyglot": 1}
        
    *   Higher values indicate it worked multiple times.
        

Advanced Topics
---------------

*   **Context Awareness**: You can enhance the plugin to detect whether the param is inserted in an attribute, JavaScript context, or HTML text, and pick payloads accordingly.
    
*   **Hybrid Approaches**: Combine the GA with machine learning models that guess the best technique by analyzing the response pattern.
    
*   **Distributed Deployment**: If you want to scale test large sites, consider distributing GA across multiple machines.
    

Limitations and Known Issues
----------------------------

*   **Request Volume**: A GA might generate many requests, possibly triggering rate-limits or WAF lockouts.
    
*   **Context**: By default, it is not fully “context-aware.” It attempts a variety of injection styles but does not automatically parse the HTML to see if it is in an attribute vs. text node.
    
*   **Session Handling**: You must ensure you are authenticated or capturing cookies in Burp so that the plugin reuses them for stored/reflected XSS checks.
    
*   **Heuristic**: The success depends on how the plugin’s evaluate\_xss() method assigns scores to partial reflections or encodings.
    

FAQ
---

1.  **Why is the plugin not finding any exploit on a known vulnerable site?**
    
    *   Check if “Proxy Capture” or “Auto-Optimize” are enabled. Also verify the parameter’s name-value is truly vulnerable, and that the GA has enough attempts (pop\_size, generations).
        
2.  **Does it handle multi-parameter injection (e.g. multiple fields)?**
    
    *   The plugin enumerates each parameter individually. Each gets its own line.
        
3.  **What about other vulnerabilities (SQLi, RCE)?**
    
    *   This plugin is focused on XSS. However, the framework could be extended to other injection types.
        

License
-------

XSS Optimizer is released under the MIT License. See the LICENSE file for details.

**Thank you for using XSS Optimizer!**For further discussion or contributions, please open issues or pull requests in the repository, or contact the author(s).
