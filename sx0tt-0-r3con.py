#!/usr/bin/env python3
"""
auto_recon.py

This script automates subdomain enumeration, URL probing, and screenshot capture
using Sublist3r, curl, and GoWitness.

Author: sx0ttGPT
"""

import argparse
import subprocess
import os
import shutil
import sys
import tempfile
import concurrent.futures
import socket
import warnings

# Suppress warnings from sublist3r and subbrute modules
warnings.filterwarnings("ignore", category=SyntaxWarning)
warnings.filterwarnings("ignore", message=".*invalid escape sequence.*")

import sublist3r  # FIX: corrected import style

def run_fast_bruteforce(domain, wordlist_file, threads, dns_timeout, wordlist_limit):
    """Fast DNS bruteforce implementation using concurrent futures"""
    print(f"[*] Loading wordlist (limit: {wordlist_limit} entries)...")
    
    try:
        with open(wordlist_file, 'r') as f:
            wordlist = [line.strip() for line in f if line.strip()][:wordlist_limit]
        
        print(f"[*] Loaded {len(wordlist)} subdomains for bruteforce")
        
        if not wordlist:
            return []
        
        found_domains = []
        processed = 0
        
        def check_subdomain(subdomain):
            """Check if a subdomain exists using DNS lookup"""
            hostname = f"{subdomain}.{domain}"
            try:
                socket.setdefaulttimeout(dns_timeout)
                result = socket.gethostbyname(hostname)
                return hostname
            except (socket.gaierror, socket.timeout):
                return None
            except Exception:
                return None
        
        print(f"[*] Starting DNS bruteforce with {threads} threads...")
        
        # Use ThreadPoolExecutor for concurrent DNS lookups
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            # Submit all tasks
            future_to_subdomain = {executor.submit(check_subdomain, subdomain): subdomain for subdomain in wordlist}
            
            # Process results as they complete
            for future in concurrent.futures.as_completed(future_to_subdomain):
                processed += 1
                
                # Progress reporting
                if processed % 500 == 0 or processed == len(wordlist):
                    print(f"[*] Bruteforce progress: {processed}/{len(wordlist)} ({processed/len(wordlist)*100:.1f}%)")
                
                result = future.result()
                if result:
                    found_domains.append(result)
                    print(f"[+] Found: {result}")
        
        print(f"[+] Bruteforce completed: {len(found_domains)} subdomains found")
        return found_domains
        
    except Exception as e:
        print(f"[!] Fast bruteforce failed: {e}")
        return []

def run_sublist3r(domain, threads, output_file, wordlist=None, dns_timeout=2.0, wordlist_limit=5000):
    """Run subdomain enumeration with Sublist3r"""
    bruteforce_enabled = wordlist is not None
    
    if bruteforce_enabled:
        print(f"[*] Enumerating subdomains for {domain} with {threads} threads (bruteforce enabled with wordlist: {wordlist})...")
        
        # Validate wordlist file exists
        if not os.path.exists(wordlist):
            print(f"[!] Wordlist file not found: {wordlist}")
            print("[*] Continuing with passive enumeration only...")
            bruteforce_enabled = False
    else:
        print(f"[*] Enumerating subdomains for {domain} with {threads} threads (passive only)...")
    
    try:
        engines = 'google,bing,baidu,yahoo,netcraft,virustotal'  # DNSDumpster removed
        
        # Always run passive enumeration first
        subdomains = sublist3r.main(
            domain, 
            threads=threads, 
            savefile=output_file, 
            ports=None, 
            silent=True, 
            verbose=False, 
            enable_bruteforce=False, 
            engines=engines
        )
        
        # Add bruteforce results if wordlist provided
        if bruteforce_enabled:
            print(f"[*] Running fast bruteforce with custom wordlist: {wordlist}")
            bruteforce_domains = run_fast_bruteforce(domain, wordlist, threads, dns_timeout, wordlist_limit)
            
            # Combine with passive results
            if subdomains:
                all_subdomains = list(set(subdomains + bruteforce_domains))
            else:
                all_subdomains = bruteforce_domains
                
            subdomains = all_subdomains
            print(f"[+] Added {len(bruteforce_domains)} subdomains from bruteforce")
        
        # Ensure we always create the output file
        if not subdomains:
            print("[!] No subdomains found by Sublist3r")
            # Create empty file for consistency
            with open(output_file, 'w') as f:
                pass
            return
            
        # Write found subdomains to file
        with open(output_file, 'w') as f:
            for sub in subdomains:
                f.write(sub + '\n')
        
        mode = "passive + bruteforce" if bruteforce_enabled else "passive"
        print(f"[+] Found {len(subdomains)} subdomains using {mode} enumeration.")
        
    except Exception as e:
        print(f"[!] Error running Sublist3r: {e}")
        # Create empty file so script can continue
        with open(output_file, 'w') as f:
            pass

def check_tool_availability(tool_name, required=True):
    """Check if a tool is available in PATH"""
    if shutil.which(tool_name) is None:
        if required:
            print(f"[!] Error: {tool_name} is not installed or not in PATH")
            sys.exit(1)
        else:
            print(f"[!] Warning: {tool_name} is not available")
            return False
    return True

def run_url_probing(subdomains_file, output_file):
    """Probe URLs using curl for maximum compatibility"""
    print("[*] Probing URLs with curl...")
    return run_curl_fallback(subdomains_file, output_file)

def run_curl_fallback(subdomains_file, output_file):
    """URL probing using curl"""
    
    if not check_tool_availability("curl", required=True):
        return
    
    # Check if subdomains file exists and has content
    if not os.path.exists(subdomains_file):
        print(f"[!] Subdomains file not found: {subdomains_file}")
        # Create empty URLs file
        with open(output_file, 'w') as f:
            pass
        return
    
    try:
        with open(subdomains_file, 'r') as f:
            subdomains = [line.strip() for line in f if line.strip()]
        
        if not subdomains:
            print("[!] No subdomains found to probe")
            # Create empty URLs file
            with open(output_file, 'w') as f:
                pass
            return
        
        print(f"[*] Probing {len(subdomains)} subdomains...")
        responsive_urls = []
        
        for i, domain in enumerate(subdomains, 1):
            if i % 5 == 0:
                print(f"[*] Progress: {i}/{len(subdomains)} domains tested")
                
            for protocol in ['http', 'https']:
                url = f"{protocol}://{domain}"
                try:
                    # Use curl with connection timeout and max time
                    result = subprocess.run([
                        "curl", "-s", "-I", 
                        "--connect-timeout", "3",
                        "--max-time", "5", 
                        "--user-agent", "Mozilla/5.0 (compatible; recon-bot)",
                        url
                    ], capture_output=True, timeout=8)
                    
                    if result.returncode == 0:
                        # Check if we got a valid HTTP response
                        output = result.stdout.decode('utf-8', errors='ignore')
                        if 'HTTP/' in output:
                            responsive_urls.append(url)
                            
                except subprocess.TimeoutExpired:
                    continue
                except Exception:
                    continue
        
        # Write results
        with open(output_file, 'w') as f:
            for url in responsive_urls:
                f.write(url + '\n')
        
        print(f"[+] Found {len(responsive_urls)} responsive URLs")
        
    except Exception as e:
        print(f"[!] Error in URL probing: {e}")
        # Create empty file so script can continue
        with open(output_file, 'w') as f:
            pass

def run_gowitness(urls_file, output_dir):
    """Run GoWitness for screenshot capture"""
    print("[*] Running GoWitness on URLs...")
    
    if not check_tool_availability("gowitness", required=False):
        print("[!] Skipping GoWitness - tool not available")
        return
    
    if not os.path.exists(urls_file) or os.path.getsize(urls_file) == 0:
        print("[!] No URLs file found or file is empty, skipping GoWitness")
        return
    
    try:
        gowitness_dir = os.path.join(output_dir, "gowitness")
        os.makedirs(gowitness_dir, exist_ok=True)
        
        # Try modern gowitness syntax first
        cmd = [
            "gowitness", "scan", "file",
            "-f", urls_file,
            "--screenshot-path", gowitness_dir,
            "--threads", "20",
            "--timeout", "10",
            "--write-db"
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        
        if result.returncode != 0:
            # Try legacy syntax
            print("[*] Modern syntax failed, trying legacy GoWitness syntax...")
            cmd = [
                "gowitness", "file",
                "-f", urls_file,
                "--timeout", "10",
                "--threads", "20",
                "--destination", gowitness_dir
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        
        if result.returncode == 0:
            print("[+] GoWitness completed successfully")
        else:
            print(f"[!] GoWitness failed: {result.stderr}")
            
    except subprocess.TimeoutExpired:
        print("[!] GoWitness timed out after 10 minutes")
    except Exception as e:
        print(f"[!] Error running GoWitness: {e}")

def run_arjun(urls_file, output_dir, threads):
    """Run Arjun for parameter discovery"""
    print("[*] Running Arjun on responsive URLs...")
    
    if not check_tool_availability("arjun", required=False):
        print("[!] Skipping Arjun - tool not available")
        return
    
    if not os.path.exists(urls_file) or os.path.getsize(urls_file) == 0:
        print("[!] No URLs file found or file is empty, skipping Arjun")
        return
    
    try:
        arjun_dir = os.path.join(output_dir, "arjun_results")
        os.makedirs(arjun_dir, exist_ok=True)
        
        with open(urls_file) as f:
            urls = [line.strip() for line in f if line.strip()]
        
        if not urls:
            print("[!] No URLs found in file, skipping Arjun")
            return
        
        print(f"[*] Running Arjun on {len(urls)} URLs with {threads} threads...")
        
        from concurrent.futures import ThreadPoolExecutor, as_completed
        import time
        
        def run_single_arjun(url):
            try:
                filename = os.path.join(arjun_dir, url.replace('://', '_').replace('/', '_') + '.json')
                cmd = ["arjun", "-u", url, "-oJ", filename]
                result = subprocess.run(cmd, capture_output=True, timeout=300)
                return f"Completed: {url}"
            except subprocess.TimeoutExpired:
                return f"Timeout: {url}"
            except Exception as e:
                return f"Error on {url}: {e}"
        
        completed = 0
        with ThreadPoolExecutor(max_workers=threads) as executor:
            future_to_url = {executor.submit(run_single_arjun, url): url for url in urls}
            for future in as_completed(future_to_url):
                completed += 1
                if completed % 5 == 0:  # Progress update every 5 completions
                    print(f"[*] Arjun progress: {completed}/{len(urls)} completed")
        
        print("[+] Arjun parameter discovery completed")
        
    except Exception as e:
        print(f"[!] Error running Arjun: {e}")

def print_banner():
    """Print ASCII banner for the tool"""
    banner = """
                                                                                                                                        
                                                                 :                                                 :                    
           .                                                    t#,                                         .,    t#,     L.            
          ;W                                                   ;##W.             j.          L             ,Wt   ;##W.    EW:        ,ft
         f#E                      GEEEEEEEL GEEEEEEEL         :#L:WE             EW,         #K:          i#D.  :#L:WE    E##;       t#E
       .E#f :KW,      L     :     ,;;L#K;;. ,;;L#K;;.        .KG  ,#D            E##j        :K#t        f#f   .KG  ,#D   E###t      t#E
      iWW;   ,#W:   ,KG    G#j       t#E       t#E           EE    ;#f           E###D.        L#G.    .D#i    EE    ;#f  E#fE#f     t#E
     L##Lffi  ;#W. jWi   .E#G#G      t#E       t#E .......  f#.     t#i.......   E#jG#W;        t#W,  :KW,    f#.     t#i E#t D#G    t#E
    tLLG##L    i#KED.   ,W#; ;#E.    t#E       t#E GEEEEEEf.:#G     GK GEEEEEEf. E#t t##f    .jffD##f t#f     :#G     GK  E#t  f#E.  t#E
      ,W#i      L#W.   i#K:   :WW:   t#E       t#E           ;#L   LW.           E#t  :K#E: .fLLLD##L  ;#G     ;#L   LW.  E#t   t#K: t#E
     j#E.     .GKj#K.  :WW:   f#D.   t#E       t#E            t#f f#:            E#KDDDD###i    ;W#i    :KE.    t#f f#:   E#t    ;#W,t#E
   .D#j      iWf  i#K.  .E#; G#L     t#E       t#E             f#D#;             E#f,t#Wi,,,   j#E.      .DW:    f#D#;    E#t     :K#D#E
  ,WK,      LK:    t#E    G#K#j      t#E       t#E              G#t              E#t  ;#W:   .D#f          L#,    G#t     E#t      .E##E
  EG.       i       tDj    j#;        fE        fE               t               DWi   ,KK:  KW,            jt     t      ..         G#E
  ,                                    :         :                                           G.                                       fE
                                                                                                                                       ,
                                                                                                                                   
                                              🔍 Automated Reconnaissance Tool v2.0 🔍        
                                            Subdomain Enum • DNS Bruteforce • URL Probing 
                                                             sx0ttGPT                                                             
"""
    print(banner)

def main():
    print_banner()
    parser = argparse.ArgumentParser(description="Automate reconnaissance using Sublist3r (with optional bruteforce), curl, GoWitness, and Arjun")
    parser.add_argument("domain", help="Target domain to enumerate")
    parser.add_argument("--threads", type=int, default=40, help="Number of threads for Sublist3r")
    parser.add_argument("--output", default="recon_output", help="Directory to store results")
    parser.add_argument("--arjun-threads", type=int, default=10, help="Number of threads for Arjun")
    parser.add_argument("--skip-gowitness", action="store_true", help="Skip GoWitness screenshot capture")
    parser.add_argument("--skip-arjun", action="store_true", help="Skip Arjun parameter discovery")
    parser.add_argument("--wordlist", help="Wordlist file for sublist3r bruteforce (enables bruteforce mode)")
    parser.add_argument("--wordlist-limit", type=int, default=5000, help="Limit wordlist to first N entries for faster bruteforce (default: 5000)")
    parser.add_argument("--dns-timeout", type=float, default=2.0, help="DNS query timeout in seconds (default: 2.0)")
    args = parser.parse_args()
    
    # Validate domain
    if not args.domain or '.' not in args.domain:
        print("[!] Error: Please provide a valid domain name")
        sys.exit(1)
    
    # Validate wordlist if provided
    if args.wordlist and not os.path.exists(args.wordlist):
        print(f"[!] Wordlist file not found: {args.wordlist}")
        print("[*] Continuing without bruteforce enumeration...")
        args.wordlist = None
    
    # Check core dependencies
    print("[*] Checking tool availability...")
    try:
        import sublist3r
        print("[+] sublist3r module found")
    except ImportError:
        print("[!] Error: sublist3r module not found. Please install it first.")
        sys.exit(1)
    
    # Check required tools
    tools_status = {}
    tools_status['curl'] = check_tool_availability("curl", required=True)
    tools_status['gowitness'] = check_tool_availability("gowitness", required=False)
    tools_status['arjun'] = check_tool_availability("arjun", required=False)
    
    # Inform user about available tools
    available_tools = [tool for tool, available in tools_status.items() if available]
    print(f"[+] Available tools: {', '.join(available_tools)}")
    
    if not tools_status['gowitness']:
        print("[!] GoWitness not available - screenshot capture will be skipped")
    if not tools_status['arjun']:
        print("[!] Arjun not available - parameter discovery will be skipped")
    
    # Create output directory
    try:
        os.makedirs(args.output, exist_ok=True)
        subdomains_file = os.path.join(args.output, "subdomains.txt")
        urls_file = os.path.join(args.output, "urls.txt")
    except Exception as e:
        print(f"[!] Error creating output directory: {e}")
        sys.exit(1)
    
    print(f"[*] Starting reconnaissance on {args.domain}")
    print(f"[*] Results will be saved in: {args.output}")
    
    try:
        # Step 1: Subdomain enumeration
        run_sublist3r(args.domain, args.threads, subdomains_file, args.wordlist, args.dns_timeout, args.wordlist_limit)
        
        # Step 2: URL probing
        run_url_probing(subdomains_file, urls_file)
        
        # Step 3: Screenshot capture (optional)
        if not args.skip_gowitness:
            run_gowitness(urls_file, args.output)
        else:
            print("[*] Skipping GoWitness as requested")
        
        # Step 4: Parameter discovery (optional)
        if not args.skip_arjun:
            run_arjun(urls_file, args.output, args.arjun_threads)
        else:
            print("[*] Skipping Arjun as requested")
        
        print("\n[+] Reconnaissance completed successfully!")
        print(f"[+] Results saved in: {args.output}")
        
        # Print summary
        try:
            if os.path.exists(subdomains_file):
                with open(subdomains_file, 'r') as f:
                    subdomain_count = len([line for line in f if line.strip()])
                print(f"[+] Subdomains found: {subdomain_count}")
            
            if os.path.exists(urls_file):
                with open(urls_file, 'r') as f:
                    url_count = len([line for line in f if line.strip()])
                print(f"[+] Responsive URLs: {url_count}")
        except:
            pass
            
    except KeyboardInterrupt:
        print("\n[!] Reconnaissance interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
