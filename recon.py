import argparse, logging, sys,time 

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
        "--targets",
        required=True,
        help="Path to file (one host per line; allow host or host:port)",
    )

    parser.add_argument(
        "--ports",
        default="80,443",
        type=str,
        help="Comma list or ranges (e.g., 80,443,8000-8100)",
    )

    parser.add_argument(
        "--workers",
        type=int,
        default=20,
        help="Concurrent TCP workers (default 20)",
    )

    parser.add_argument(
        "--http",
        action="store_true",
        help="Probe HTTP(S) services and extract title, meta description, Server header",
    )

    parser.add_argument(
        "--tls",
        action="store_true",
        help="Attempt TLS retrieval for ports that speak TLS",
    )

    parser.add_argument(
        "--output",
        deault="recon_results",
        help="Path prefix for results; tool writes PREFIX.results.json and PREFIX.results.csv",
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="Per-connection timeout in seconds (float OK)",
    )

    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose debug logging"
    )

    return parser.parse_args()

def parse_ports(port_arg):

    ports=set()
    parts = port_arg.split("-")
    for part in parts:
        if "-" in part:
            start, end = map(int, part.split("-",))
            ports.update(range(start),end + 1)
        else:
            ports.add(int(part))
    return sorted(list(ports))

"""
Reads the target file ad returns a list of targets.
"""
def targets(file_path):
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
    


        
def main():
    args = parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Verbose logging enabled")

    print(f"[*] startiing Recon tool")

    target_list = read_targets(args.targets)
    port_list = parse_ports(args.ports)

    logging.info(f"Loaded {len(target_list)} targets and {len(port_list)} ports to scan.")

    print("[*] Scan complete.")

if __name__ == "__main__":
    main()

