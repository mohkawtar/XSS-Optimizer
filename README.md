# XSS-Optimizer
XSS Optimizer (GA-Driven XSS Testing Plugin)
XSS Optimizer is a Burp Suite extension that leverages Genetic Algorithms (GA) to systematically test and optimize Cross-Site Scripting (XSS) injection vectors. Rather than relying on purely static payload lists, the plugin evolves payloads and obfuscation techniques based on actual feedback from the target application’s responses.

Table of Contents
Overview

Key Features

Installation

Usage

Capturing Requests

Launching GA Optimization

Auto-Optimize

Context Menu Integration

How It Works

Genetic Algorithm Flow

Payload and Obfuscation

Stored XSS Checks

Architecture and Components

Disclaimer

License

Contact / Contributing

Overview
XSS Optimizer automates the process of finding exploitable XSS (Cross-Site Scripting) by using evolutionary search. Instead of sequentially testing static payloads, it:

Generates an initial population of potential attack vectors (payload + obfuscation + length).

Evaluates each vector by injecting it into the request and analyzing the server’s response.

Adapts the next generation via crossover (combining partial traits from the top-performing vectors) and mutation (random adjustments to introduce diversity).

Repeats until it either finds a working exploit or hits a maximum iteration threshold.

Key Features
Genetic Algorithm (GA) Engine: Adaptive evolution of XSS payloads (script-based, HTML-embedded, attribute-based, etc.).

Context Menu Integration in Burp: Right-click a request to “Send to XSS Optimizer.”

Auto-Capturing from Proxy: Automatically picks up requests (if enabled) to generate potential test vectors.

Stored and Reflected XSS coverage, including basic “post-check” to verify if a payload is stored in the target application.

Result Logging: Outputs a CSV log containing attempts, final status, and best payload used.

Installation
Download/Clone this repository.

Compile or place the Python script (if you are using Jython-based extension):

Ensure you have Jython 2.7+ set up in Burp’s Extender > Options > Python Environment.

In Burp Suite:

Go to Extender > Extensions > Add.

Select Extension Type = “Python”.

Locate and load the XSSOptimizer.py (or your final .py) script.

You should see a tab labeled “XSS GA” (or whatever name you configured).

Check the Extender Output tab for confirmation logs that the plugin loaded successfully.

Usage
Capturing Requests
Enable Proxy Capture by checking “Proxy Capture” in the plugin’s UI.

Navigate your target application in Burp’s Proxy.

Each request containing parameters is automatically listed in the plugin’s table (except cookies).

The plugin enumerates all parameters found via Burp’s analyzeRequest API.

Launching GA Optimization
Select one of the entries in the plugin’s table.

Click “Optimize Selected”.

The plugin spawns a Genetic Algorithm search for that request + parameter.

Watch the table’s “Payload,” “Code,” and “Result” columns update as the GA iterates.

If it finds a working exploit (XSS injection confirmed), the “Result” becomes exploitable.

Auto-Optimize
Check the “Auto-Optimize” box if you want the GA to run automatically whenever a new request is added to the table.

Context Menu Integration
Right-click on any request in Burp (e.g., in Proxy History, Target, etc.).

Choose “Send to XSS Optimizer”.

The plugin enumerates parameters from that request and adds them to the table with the “Param” column showing each name=value.

How It Works
Genetic Algorithm Flow
rust
Copiar
1. Initialize population -> 2. Evaluate each (inject + analyze) -> 
3. Sort by fitness (score) -> 4. Select top K -> 
5. Crossover + Mutate -> 6. New population -> repeat
Scoring (Fitness):

If the response includes the GA’s unique XSS_#### token unescaped and the status code is 200, we assign a high score (e.g., 10).

Partial reflection or other indicators yield intermediate scores.

HTTP errors or unreflected attempts get lower or negative scores.

Bonus: The plugin tracks historically successful (URL + technique) pairs, awarding extra points to techniques that previously succeeded on that URL.

Payload and Obfuscation
Payload is chosen from a static array COMMON_PAYLOADS (script-based, attribute-based, etc.) but dynamically mutated/combined with techniques like:

url (URL-encoding),

html (HTML-escaping),

js_obfuscate,

polyglot, and more.

Stored XSS Checks
After injection, if the immediate response is not exploitable, the plugin may do a “post-check” on typical stored-XSS URLs (like /dvwa/vulnerabilities/xss_s/) to see if XSS_#### appears in the final rendered page, indicating a stored injection.

Architecture and Components
Burp Integration:

Implements IBurpExtender, IHttpListener, ITab, and IContextMenuFactory.

Provides the UI tab and manages request hooking.

GA Module:

Coordinates population creation, evaluation, selection, crossover, and mutation.

Runs in a background thread (or multiple threads) so as not to block the Burp UI.

Request Analyzer:

Parses request parameters, updates them with candidate payloads, sends them via makeHttpRequest.

Response Scoring:

Follows up to one redirect if present.

Looks for unique_id reflection or script execution signals.

Disclaimer
Educational Purpose: This plugin is intended for authorized security testing and research.

Responsible Usage: Only test targets you own or have explicit permission to assess.

The authors disclaim responsibility for any illegal or malicious use of this code.

License
MIT License (or whichever license you choose)

Contact & Contributing
Issues / Feature Requests: Please open an issue on GitHub.

Pull Requests: Contributions for new obfuscation techniques, payload expansions, or GA improvements are welcome.

For any questions or suggestions, feel free to reach out via GitHub or email.

Thank you for trying out XSS Optimizer! We hope this helps your security assessments become more adaptive, thorough, and efficient.






