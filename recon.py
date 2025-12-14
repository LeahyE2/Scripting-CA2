import argparse, logging, sys,time, socket,json, concurrent.futures, csv 

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stderr)]
)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Recon tool for network reconnaissance."
    )

    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose debug logging"
    )

    subparsers = parser.add_subparsers(
        dest = "command",
        help='Available commands'
    )

    scan_parser = subparsers.add_parser(
        "scan",
        help="Run the comprehensive recon scan"
    )

    scan_parser.set_defaults(func=run_scan)

    scan_parser.add_argument(
        "--targets",
        required=True,
        help="Path to file (one host per line; allow host or host:port)",
    )

    scan_parser.add_argument(
        "--ports",
        default="80,443",
        type=str,
        help="Comma list or ranges (e.g., 80,443,8000-8100)",
    )

    scan_parser.add_argument(
        "--workers",
        type=int,
        default=20,
        help="Concurrent TCP workers (default 20)",

    )

    scan_parser.add_argument(
        "--http",
        action="store_true",
        help="Probe HTTP(S) services and extract title, meta description, Server header",
    )

    scan_parser.add_argument(
        "--tls",
        action="store_true",
        help="Attempt TLS retrieval for ports that speak TLS",
    )

    scan_parser.add_argument(
        "--output",
        default="recon_results",
        help="Path prefix for results; tool writes PREFIX.results.json and PREFIX.results.csv",
    )

    scan_parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="Per-connection timeout in seconds (float OK)",
    )

# Flags for reilience/resume

    scan_parser.add_argument(
        "--resume",
        action="store_true",
        help="If set,resume previous scan results from output files",
    )

    scan_parser.add_argument(
        "--retry",
        type=int,
        default=1,
        help="Number of times(N) to retry failures",
    )


    return parser.parse_args()

def parse_ports(port_arg):

    ports=set()
    parts = port_arg.split(",")

    for part in parts:
        part = part.strip()

        if not part:
            continue

        if "-" in part:
            try:
                start, end = map(int, part.split("-"))
                if start > end:
                    start, end = end, start
                ports.update(range(start, end + 1))
            except ValueError:
                logging.error(f"Invalid port range format: {part}") 
        else:
        
            try:
                ports.add(int(part))
            except ValueError:
                logging.error(f"Invalid port value: {part}")

    return sorted(list(ports))

"""
Reads the target file ad returns a list of targets.
"""
def read_targets(file_path):
    try:
        with open(file_path, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]
        return targets
    except FileNotFoundError:
        logging.error(f"Target file not found: {file_path}")
        sys.exit(1)
    
def run_scan(args):
    """
    logic for recon scan tool
    """
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Verbose logging enabled")
    print(f"[*] starting Recon tool at {time.strftime('%X' )}")

    target_list = read_targets(args.targets)
    port_list = parse_ports(args.ports)

    logging.info(f"Loaded {len(target_list)} targets and {len(port_list)} ports to scan.") 

    all_scan_results =  []

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
    
        tasks = [
            executor.submit(scan_port, target.split(':')[0], port, args.timeout, args.retry)
            for target in target_list
            for port in port_list
        ]

        
        logging.info(f"Total scan tasks created {len(tasks)}")

        completed_count = 0
        total_tasks = len(tasks)

        for future in concurrent.futures.as_completed(tasks):
            completed_count += 1

            try:
                result = future.result()
                all_scan_results.append(result)

            except Exception as exc:
                logging.error(f"Task generated an unexpected exception: {exc}", exc_info=args.verbose)

            if completed_count % 50 == 0 or completed_count == total_tasks:
                print(f"\r[*] Progress: {completed_count}/{total_tasks} tasks completed", end="", file=sys.stderr)
            
    print("", file=sys.stderr)
    logging.info(f"Scan finished. Found {len([r for r in all_scan_results if r['status'] == 'open'])} open services.") 
        
    write_json_output(all_scan_results, args.output)
    write_csv_output(all_scan_results, args.output)

    print("[*] Scan complete.")

def scan_port(host, port, timeout, retry_count):
    """
    Attempts a TCP connection scan on the provided host along with tries 
    """
    result = {
        "host": host,
        "port": port,
        "status": "filtered/timeout",
        "duration": None,
        "service_hint": None,
        "banner": None,
        "http": None,
        "tls": None,

    }

    for attempt in range(retry_count):
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)

            start_time = time.time()
            err_code = s.connect_ex((host, port))
            duration = time.time() - start_time
            result["duration"] = round(duration, 3)
            
            if err_code == 0:
                result["status"] = "open"
                
                if port in (80, 8080):
                    result["service_hint"] = "http"
                elif port in (443, 8443):
                    result["service_hint"] = "https/tls"
                else:
                    result["service_hint"] = "tcp_open" 
                
                logging.debug(f"Port {port} on {host} is open.")

                break

            elif err_code in [111, 104, 61]:
                result["status"] = "closed"
                logging.debug(f"Port {port} on {host} is closed.")
                break
            else:
                if attempt < retry_count - 1:
                    wait_time = 2 ** attempt
                    time.sleep(wait_time)
                    logging.debug(f"Target {host}:{port} timed out/filtered.Retrying in {wait_time}s... ")
                else:
                    result["status"] = "filtered/timeout"

        except Exception as e:
            result["status"] = "error"
            logging.error(f"Unexpected erorror scanning {host}:{port}: {e}", exc_info=False)
            break

        finally:
            if s:
                s.close()
            
    return result

def write_json_output(data, prefix):
    pass

def write_csv_output(data, prefix):
    pass


def main():
    args = parse_args()

    if args.command is None:

        print("No command provided, please try 'python recon -h' for help")
        sys.exit (1)

    args.func(args)
    

if __name__ == "__main__":
    main()