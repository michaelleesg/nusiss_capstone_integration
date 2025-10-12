"""IOC extraction and normalization agent."""

from .base_agent import BaseAgent
from ...state import GraphState
from ...tools.ioc import extract_and_normalize, IOCInput


class IOCAgent(BaseAgent):
    """Agent responsible for IOC extraction and normalization."""

    def __init__(self):
        super().__init__("ioc")

    def get_system_prompt(self) -> str:
        return """You are an IOC (Indicators of Compromise) extraction agent.

Extract and normalize IOCs from threat intelligence content:

NETWORK IOCs:
URLS:
- Malicious websites
- C2 servers
- Payload delivery URLs
- Phishing sites
- Handle defanged URLs (hxxp, [.])

DOMAINS:
- C2 domains
- Malicious domains
- DGA domains
- Sinkholed domains
- Handle defanged domains

IP ADDRESSES:
- C2 server IPs
- Malicious IP addresses
- Both IPv4 and IPv6
- Skip private ranges unless in threat context

FILE HASHES:
- MD5, SHA1, SHA256, SHA512
- Malware samples
- Document hashes
- Validate hash lengths

HOST-BASED IOCs:
FILES AND PATHS:
- Malicious file paths
- Dropped file locations
- Temporary file paths
- Configuration files
- Log file paths

PROCESSES:
- Malicious process names
- Process command lines
- Process arguments
- Service names

REGISTRY KEYS:
- Registry key paths
- Registry value names
- Persistence registry entries
- Configuration registry keys

COMMANDS:
- Command line executions
- PowerShell commands
- Batch commands
- Shell commands

EMAIL-BASED IOCs:
EMAIL ADDRESSES:
- Sender addresses
- Reply-to addresses
- Malicious email addresses



Normalize all IOCs to canonical forms and deduplicate."""

    def process(self, state: GraphState) -> GraphState:
        """Extract IOCs first, then use LLM for contextual filtering."""
        # Set flag immediately to prevent infinite loops
        state.extracted["iocs_extraction_attempted"] = True

        try:
            text = state.parsed.get("text", "") if state.parsed else ""

            if not text.strip():
                self.logger.warning("No text content available for IOC extraction")
                self._set_empty_iocs(state)
                return state

            # Step 1: Extract all IOCs using pattern matching and basic filtering
            metadata = {
                "url": state.url,
                "title": state.extracted.get("title", ""),
                "summary": state.extracted.get("summary", ""),
                "source": "intelligence_report"
            }
            ioc_input = IOCInput(text=text, metadata=metadata)
            initial_iocs = extract_and_normalize(ioc_input)

            # Step 2: Use LLM to analyze extracted IOCs with context for source filtering
            summary = state.extracted.get("summary", "")
            title = state.extracted.get("title", "")

            # Prepare IOC data for LLM analysis
            all_iocs = {
                "urls": initial_iocs.urls,
                "domains": initial_iocs.domains,
                "ips": initial_iocs.ips,
                "hashes": initial_iocs.hashes,
                "file_paths": initial_iocs.file_paths,
                "processes": initial_iocs.processes,
                "registry_keys": initial_iocs.registry_keys,
                "commands": initial_iocs.commands,
                "email_addresses": initial_iocs.email_addresses,
            }

            # Get pre-filtered non-routable IPs from the IOC extraction tool
            pre_excluded_ips = getattr(initial_iocs, 'non_routable_ips', [])

            # Only do LLM filtering if we have IOCs to filter (including routable IPs for context filtering)
            if any([all_iocs["urls"], all_iocs["domains"], all_iocs["ips"], all_iocs["hashes"],
                   all_iocs["file_paths"], all_iocs["processes"], all_iocs["registry_keys"],
                   all_iocs["commands"], all_iocs["email_addresses"]]):
                try:
                    filter_result = self._filter_iocs_with_llm(all_iocs, summary, title, state.url, text)
                    filtered_iocs = filter_result["filtered"]
                    excluded_iocs = filter_result["excluded"]
                    self.logger.info("LLM IOC filtering completed successfully")
                except Exception as e:
                    # If LLM filtering fails (timeout, error), use the initial filtered IOCs
                    self.logger.warning(f"LLM IOC filtering failed ({e}), using pattern-based filtering results")
                    filtered_iocs = {
                        "urls": initial_iocs.urls,
                        "domains": initial_iocs.domains,
                        "ips": initial_iocs.ips,
                        "hashes": initial_iocs.hashes,
                        "file_paths": initial_iocs.file_paths,
                        "processes": initial_iocs.processes,
                        "registry_keys": initial_iocs.registry_keys,
                        "commands": initial_iocs.commands,
                        "email_addresses": initial_iocs.email_addresses,
                    }
                    excluded_iocs = {k: [] for k in filtered_iocs.keys()}

                # Add pre-filtered non-routable IPs to exclusions
                if pre_excluded_ips:
                    excluded_iocs["ips"].extend(pre_excluded_ips)
            else:
                filtered_iocs = {
                    "urls": initial_iocs.urls,
                    "domains": initial_iocs.domains,
                    "ips": initial_iocs.ips,
                    "hashes": initial_iocs.hashes,
                    "file_paths": initial_iocs.file_paths,
                    "processes": initial_iocs.processes,
                    "registry_keys": initial_iocs.registry_keys,
                    "commands": initial_iocs.commands,
                    "email_addresses": initial_iocs.email_addresses,
                }
                excluded_iocs = {
                    "urls": [], "domains": [], "ips": pre_excluded_ips, "hashes": [],
                    "file_paths": [], "processes": [], "registry_keys": [], "commands": [],
                    "email_addresses": []
                }

            # Create final IOC result
            from ...tools.ioc import IOCOutput
            ioc_result = IOCOutput(
                    urls=filtered_iocs["urls"],
                    domains=filtered_iocs["domains"],
                    ips=filtered_iocs["ips"],
                    hashes=filtered_iocs["hashes"],
                    file_paths=filtered_iocs.get("file_paths", []),
                    processes=filtered_iocs.get("processes", []),
                    registry_keys=filtered_iocs.get("registry_keys", []),
                    commands=filtered_iocs.get("commands", []),
                    email_addresses=filtered_iocs.get("email_addresses", []),
                )

            # Store the filtered IOCs with exclusions
            state.extracted["iocs"] = {
                "urls": ioc_result.urls,
                "domains": ioc_result.domains,
                "hashes": ioc_result.hashes,
                "ips": ioc_result.ips,
                "file_paths": ioc_result.file_paths,
                "processes": ioc_result.processes,
                "registry_keys": ioc_result.registry_keys,
                "commands": ioc_result.commands,
                "email_addresses": ioc_result.email_addresses,
                "excluded": excluded_iocs
            }
            state.extracted["iocs_extraction_attempted"] = True

            # Generate evidence for found IOCs
            evidence = []
            all_iocs = (ioc_result.urls + ioc_result.domains + ioc_result.hashes + ioc_result.ips +
                       ioc_result.file_paths + ioc_result.processes + ioc_result.registry_keys +
                       ioc_result.commands + ioc_result.email_addresses)
            for ioc in all_iocs:  # Process all IOCs for evidence
                if ioc in text:
                    start_pos = text.find(ioc)
                    start = max(0, start_pos - 50)
                    end = min(len(text), start_pos + len(ioc) + 50)
                    snippet = text[start:end].strip()
                    if len(snippet) > 200:
                        snippet = snippet[:200] + "..."
                    evidence.append({"loc": "body", "text": snippet})

            state.evidence.extend(evidence)

            self.log_processing("IOC extraction complete using LLM guidance", {
                "urls": len(ioc_result.urls),
                "domains": len(ioc_result.domains),
                "hashes": len(ioc_result.hashes),
                "ips": len(ioc_result.ips),
                "file_paths": len(ioc_result.file_paths),
                "processes": len(ioc_result.processes),
                "registry_keys": len(ioc_result.registry_keys),
                "commands": len(ioc_result.commands),
                "email_addresses": len(ioc_result.email_addresses),
                "token_usage": self.token_usage
            })

            return state

        except Exception as e:
            self.logger.error(f"Error in IOC extraction: {e}")
            # Fallback to basic extraction without LLM filtering
            try:
                text = state.parsed.get("text", "") if state.parsed else ""
                metadata = {
                    "url": state.url,
                    "title": state.extracted.get("title", ""),
                    "summary": state.extracted.get("summary", ""),
                    "source": "intelligence_report"
                }
                ioc_input = IOCInput(text=text, metadata=metadata)
                ioc_result = extract_and_normalize(ioc_input)

                state.extracted["iocs"] = {
                    "urls": ioc_result.urls,
                    "domains": ioc_result.domains,
                    "hashes": ioc_result.hashes,
                    "ips": ioc_result.ips,
                    "file_paths": ioc_result.file_paths,
                    "processes": ioc_result.processes,
                    "registry_keys": ioc_result.registry_keys,
                    "commands": ioc_result.commands,
                    "email_addresses": ioc_result.email_addresses,
                    "excluded": {
                        "urls": [], "domains": [], "ips": [], "hashes": [],
                        "file_paths": [], "processes": [], "registry_keys": [], "commands": [],
                        "email_addresses": []
                    }
                }
                state.extracted["iocs_extraction_attempted"] = True
            except Exception as fallback_error:
                self.logger.error(f"Fallback IOC extraction also failed: {fallback_error}")
                self._set_empty_iocs(state)

            return state

    def _filter_iocs_with_llm(self, iocs: dict, summary: str, title: str, source_url: str, context_text: str) -> dict:
        """Use LLM to filter IOCs based on context, removing source domains and false positives."""

        system_prompt = r"""You are a cybersecurity analyst reviewing extracted IOCs (Indicators of Compromise) from threat intelligence reports. Your task is to filter out false positives and source organization domains.

CRITICAL INSTRUCTIONS FOR NETWORK IOCs:
1. DO NOT alter the IOCs. Treat URLs and Domains as SEPARATE ENTITIES.
2. REMOVE domains and URLs that belong to the REPORTING organization (the source of this intelligence)
3. KEEP ALL malicious infrastructure, attack URLs, and C2 domains used by threat actors
4. EVALUATE URLs AS COMPLETE ENTITIES - a legitimate domain can host malicious content via specific paths/parameters
5. KEEP URLs with parameters, query strings, or attack-specific paths regardless of base domain
6. KEEP defanged URLs and URLs mentioned in IOC sections as malicious infrastructure
7. For domains alone (without paths), only exclude if they are clearly source/reporting organizations
8. Keep file hashes as they are rarely false positives
9. IP addresses are handled separately with deterministic classification

CRITICAL DOMAIN VS FILE/SIGNATURE DISTINCTION:
10. **EXCLUDE NON-DOMAINS MISCLASSIFIED AS DOMAINS**:
    - File names with ANY extensions (.exe, .dll, .class, .jar, .php, .html, .js, .css, .txt, .doc, .pdf, .dat, .bin, etc.) are NOT domains
    - Executable names (bitsadmin.exe, certutil.exe, powershell.exe, cmd.exe, java.exe, etc.) are NOT domains
    - Detection signatures (Backdoor.Meterpreter, Exploit.CitrixNetScaler, Trojan.METASTAGE, etc.) are NOT domains
    - .NET class names (System.Net.WebClient, client.downloadfile, net.webclient, etc.) are NOT domains
    - Method/function names (template.new, dti.callback, etc.) are NOT domains
    - Security product detections and rule names are NOT domains
    - If it contains "DOWNLOADER", "METHODOLOGY", "BACKDOOR", "EXPLOIT", "TROJAN" it's likely a detection signature, NOT a domain
11. **ACTUAL DOMAINS must have**:
    - Valid internet TLDs (.com, .org, .net, .gov, .edu, .io, .tk, .xyz, etc.)
    - Represent actual network infrastructure, C2 servers, or malicious websites
    - Be mentioned as destinations for network communication, not as executable files
    - Examples of VALID domains: exchange.dumb1.com, malicious-site.tk, c2-server.io
    - Examples of INVALID "domains": bitsadmin.exe, Backdoor.Meterpreter, System.Net.WebClient

CRITICAL INSTRUCTIONS FOR HOST-BASED IOCs:
12. KEEP file paths that are:
    - Malware drop locations (C:\temp\malware.exe, /tmp/backdoor)
    - Suspicious file locations mentioned in attack context
    - Files created or modified by malware
    - EXCLUDE: URL paths (/login, /contact-us), version numbers (/1.0, /2.32.4), web references
13. KEEP processes that are:
    - Malicious executables mentioned in threat context
    - Legitimate processes used maliciously (powershell.exe with encoded commands)
    - Custom malware process names
    - EXCLUDE: Document fragments, administrative text, organization names as processes
14. **REGISTRY KEY VALIDATION - KEEP registry keys that are**:
    - Actual registry key paths (e.g., "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run")
    - Registry value names and data used by malware
    - Persistence registry entries without command syntax
    - **EXCLUDE THESE AS REGISTRY KEYS**:
        - Windows commands that modify registry (e.g., "reg add", "sc create", "net start")
        - Batch scripts or command sequences
        - Command lines that happen to contain registry paths
        - Multi-line scripts with registry operations mixed with other commands
    - **MOVE TO COMMANDS**: If it contains "sc create", "reg add", "net start", etc., it's a command not a registry key
15. **COMMAND VALIDATION - KEEP command line executions that are**:
    - Actual commands with parameters (e.g., "powershell $client = new-object System.Net.WebClient...")
    - Specific commands with URLs (e.g., "cmd /c bitsadmin /transfer bbbb http://...")
    - Download commands (e.g., "certutil -urlcache -split -f http://...", 'wget http://xxx")
    - Complete command line strings that attackers executed
    - Windows service commands (e.g., "sc create", "sc failure", "sc description")
    - Registry modification commands (e.g., "reg add", "reg delete")
    - Network commands (e.g., "net start", "net stop")
    - Batch scripts or multi-line command sequences
    - **EXCLUDE THESE NON-COMMANDS**:
        - Detection rule names (e.g., "POWERSHELL DOWNLOADER (METHODOLOGY)")
        - Security product signatures (e.g., "SUSPICIOUS BITSADMIN USAGE B (METHODOLOGY)")
        - MITRE ATT&CK technique references (e.g., "PowerShell (T1086), Scripting (T1064)")
        - Generic descriptions like "PowerShell downloading files with Net.WebClient" or "XXX has used Powershell"
        - Documentation fragments or analysis text
16. APPLY CONTEXT: Only include if it's an actual executable command, not a description or detection name

CRITICAL INSTRUCTIONS FOR EMAIL-BASED IOCs:
17. KEEP email addresses that are:
    - Sender addresses from phishing/malicious emails
    - Command & control email addresses
    - EXCLUDE: Legitimate contacts, reporting organization emails, example addresses, emails from reputable entities such as 
      governments such as .gov unless they are mentioned as malicious.
18. KEEP email subjects that are:
    - Actual phishing email subject lines used in campaigns
    - Social engineering email subjects
    - EXCLUDE: Document titles, section headers, generic references to "email subject"

IMPORTANT DISTINCTIONS:
- URLs vs Domains: A URL with specific paths/parameters can be malicious even if the base domain is legitimate
- KEEP: Complete URLs used for attacks, regardless of whether the domain itself is legitimate
- KEEP: URLs with query parameters, especially those mentioned as attack infrastructure
- REMOVE: Only domains/URLs that belong to the reporting organization itself
- Context matters: Look for phrases like "threat actors guide victims to visit" or "malicious app"

Pay special attention to the document summary and source URL to identify the reporting organization."""

        user_prompt = f"""
DOCUMENT CONTEXT:
- Source URL: {source_url}
- Title: {title}
- Summary: {summary}

EXTRACTED IOCs TO REVIEW:
URLs ({len(iocs['urls'])}): {iocs['urls']}
Domains ({len(iocs['domains'])}): {iocs['domains']}
IPs ({len(iocs['ips'])}): {iocs['ips']}
Hashes ({len(iocs['hashes'])}): {iocs['hashes']}
File Paths ({len(iocs['file_paths'])}): {iocs['file_paths']}
Processes ({len(iocs['processes'])}): {iocs['processes']}
Registry Keys ({len(iocs['registry_keys'])}): {iocs['registry_keys']}
Commands ({len(iocs['commands'])}): {iocs['commands']}
Email Addresses ({len(iocs['email_addresses'])}): {iocs['email_addresses']}

Based on the context above, please filter these IOCs and return the results in JSON format:

{{
  "keep": {{
    "urls": ["list", "of", "malicious", "urls"],
    "domains": ["list", "of", "malicious", "domains"],
    "ips": ["list", "of", "malicious", "ips"],
    "hashes": ["list", "of", "malicious", "hashes"],
    "file_paths": ["list", "of", "malicious", "file_paths"],
    "processes": ["list", "of", "malicious", "processes"],
    "registry_keys": ["list", "of", "malicious", "registry_keys"],
    "commands": ["list", "of", "malicious", "commands"],
    "email_addresses": ["list", "of", "malicious", "email_addresses"],
  }},
  "exclude": {{
    "urls": [{{"ioc": "excluded_url", "reason": "why excluded"}}],
    "domains": [{{"ioc": "excluded_domain", "reason": "why excluded"}}],
    "ips": [{{"ioc": "excluded_ip", "reason": "why excluded"}}],
    "hashes": [{{"ioc": "excluded_hash", "reason": "why excluded"}}],
    "file_paths": [{{"ioc": "excluded_path", "reason": "why excluded"}}],
    "processes": [{{"ioc": "excluded_process", "reason": "why excluded"}}],
    "registry_keys": [{{"ioc": "excluded_key", "reason": "why excluded"}}],
    "commands": [{{"ioc": "excluded_command", "reason": "why excluded"}}],
    "email_addresses": [{{"ioc": "excluded_email", "reason": "why excluded"}}],
  }},
  "reasoning": "Brief explanation of what was filtered and why"
}}

IMPORTANT FILTERING RULES:
- Remove domains/URLs belonging to the REPORTING organization (e.g., government agencies when they are the source)
- KEEP complete URLs that are attack infrastructure, including their full paths and parameters
- KEEP URLs with query parameters or specific paths, even if the base domain is a legitimate service
- EVALUATE each URL as a complete entity - parameters and paths can make legitimate domains malicious
- DO NOT strip or ignore URL parameters when evaluating maliciousness
- **CRITICAL**: Look at the TLDs for domains and EXCLUDE these common false positives as domains:
  * Executable names: bitsadmin.exe, certutil.exe, powershell.exe, cmd.exe, java.exe
  * Detection signatures: Backdoor.Meterpreter, Exploit.CitrixNetScaler, Trojan.METASTAGE
  * .NET classes: System.Net.WebClient, client.downloadfile, net.webclient
  * File names: x32.dat, template.new, install.bat
- **CRITICAL**: Commands are executed via CLI and EXCLUDE these as commands:
  * Detection names: "POWERSHELL DOWNLOADER (METHODOLOGY)", "SUSPICIOUS BITSADMIN USAGE"
  * Generic descriptions: "PowerShell downloading files with Net.WebClient"
  * MITRE references: "PowerShell (T1086), Scripting (T1064)"
- **CRITICAL**: MOVE FROM REGISTRY KEYS TO COMMANDS:
  * Windows service commands: "sc create", "sc failure", "sc description"
  * Registry commands: "reg add", "reg delete"
  * Network commands: "net start", "net stop"
  * Multi-line batch scripts containing these commands
- For each excluded IOC, provide a specific reason (e.g., "executable name misclassified as domain", "detection signature not actual domain")
"""

        try:
            response = self.call_llm(system_prompt, user_prompt)

            # Extract JSON from response
            import json
            if "```json" in response:
                json_start = response.find("```json") + 7
                json_end = response.find("```", json_start)
                json_text = response[json_start:json_end].strip()
            else:
                # Try to find JSON in the response
                json_start = response.find("{")
                json_end = response.rfind("}") + 1
                json_text = response[json_start:json_end] if json_start != -1 and json_end > json_start else response

            filtered_result = json.loads(json_text)

            # Log the filtering reasoning
            if "reasoning" in filtered_result:
                self.logger.info(f"LLM IOC filtering reasoning: {filtered_result['reasoning']}")

            keep_list = filtered_result.get("keep", {})
            exclude_list = filtered_result.get("exclude", {})

            # Process exclusions to handle both old format (strings) and new format (objects with reasons)
            def process_exclusions(exclusions):
                if not exclusions:
                    return []
                # Handle both formats: ["string"] or [{"ioc": "string", "reason": "why"}]
                processed = []
                for item in exclusions:
                    if isinstance(item, str):
                        # Old format - convert to new format with generic reason
                        processed.append({"ioc": item, "reason": "excluded by LLM filter"})
                    elif isinstance(item, dict) and "ioc" in item:
                        # New format - use as is
                        processed.append(item)
                return processed

            return {
                "filtered": {
                    "urls": keep_list.get("urls", []),
                    "domains": keep_list.get("domains", []),
                    "ips": keep_list.get("ips", []),
                    "hashes": keep_list.get("hashes", []),
                    "file_paths": keep_list.get("file_paths", []),
                    "processes": keep_list.get("processes", []),
                    "registry_keys": keep_list.get("registry_keys", []),
                    "commands": keep_list.get("commands", []),
                    "email_addresses": keep_list.get("email_addresses", []),
                },
                "excluded": {
                    "urls": process_exclusions(exclude_list.get("urls", [])),
                    "domains": process_exclusions(exclude_list.get("domains", [])),
                    "ips": process_exclusions(exclude_list.get("ips", [])),
                    "hashes": process_exclusions(exclude_list.get("hashes", [])),
                    "file_paths": process_exclusions(exclude_list.get("file_paths", [])),
                    "processes": process_exclusions(exclude_list.get("processes", [])),
                    "registry_keys": process_exclusions(exclude_list.get("registry_keys", [])),
                    "commands": process_exclusions(exclude_list.get("commands", [])),
                    "email_addresses": process_exclusions(exclude_list.get("email_addresses", [])),
                }
            }

        except Exception as e:
            self.logger.error(f"Error in LLM IOC filtering: {e}")
            # Return original IOCs if filtering fails
            return {
                "filtered": iocs,
                "excluded": {
                    "urls": [], "domains": [], "ips": [], "hashes": [],
                    "file_paths": [], "processes": [], "registry_keys": [], "commands": [],
                    "email_addresses": []
                }
            }

    def _set_empty_iocs(self, state: GraphState):
        """Set empty IOC structure in state."""
        state.extracted["iocs"] = {
            "urls": [],
            "domains": [],
            "hashes": [],
            "ips": [],
            "file_paths": [],
            "processes": [],
            "registry_keys": [],
            "commands": [],
            "email_addresses": [],
            "excluded": {
                "urls": [], "domains": [], "ips": [], "hashes": [],
                "file_paths": [], "processes": [], "registry_keys": [], "commands": [],
                "email_addresses": []
            }
        }
        state.extracted["iocs_extraction_attempted"] = True