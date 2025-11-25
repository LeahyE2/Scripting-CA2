import argparse, socket, json, time, os

def parse_args():
    parser = argparse.ArgumentParser(
        description="Example argparse parser for network scanning flags"
    )

    parser.add_argument(
        "--targets",
        required=True,
        help="Path to file (one host per line; allow host or host:port)",
        type=str
    )

    parser.add_argument(
        "--ports",
        required=True,
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
        help="Path prefix for results; tool writes PREFIX.results.json and PREFIX.results.csv",
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="Per-connection timeout in seconds (float OK)",
    )

    return parser.parse_args()

def targets(file_path):
    if not os.path.isfile(file_path):
        print(f"Error the file '{file_path}' was not found")
        return
    with open(file_path, "r") as f:
        for line_num, line in enumerate (f,1):
            raw_target = line.strip() #This removes whitespace from start and end

            if not raw_target: # Skips empty lines
                continue
            
            yield raw_target 



def main():
    args = parse_args()
    print("Arguments Received:")
    print(f"  targets : {args.targets}")
    print(f"  ports   : {args.ports}")
    print(f"  workers : {args.workers}")
    print(f"  http    : {args.http}")
    print(f"  tls     : {args.tls}")
    print(f"  output  : {args.output}")
    print(f"  timeout : {args.timeout}")


if __name__ == "__main__":
    main()

