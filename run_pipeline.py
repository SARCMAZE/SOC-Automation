import os
import subprocess
import sys
import time


def print_stage(step: int, total: int, title: str):
    bar = "#" * step + "-" * (total - step)
    print(f"\nStep {step}/{total}: {title} [{bar}]")


def run_l1():
    print_stage(1, 4, "Running L1 Layer with relaxed default thresholds")
    l1_out = os.path.join(os.getcwd(), "l1_runtime_output.jsonl")
    subprocess.run([sys.executable, "L1.balanced.py", "--min-score", "8", "--output", l1_out], check=True)
    return l1_out


def run_l2():
    print_stage(2, 4, "Running L2 Layer")
    return None


def start_api_server():
    print("\nStarting local API server...")
    return subprocess.Popen([sys.executable, "api_server.py"], cwd=os.getcwd())


def start_frontend():
    print("\nStarting local React frontend...")
    npm_command = "npm.cmd" if os.name == "nt" else "npm"
    try:
        return subprocess.Popen(
            [npm_command, "run", "dev", "--", "--host", "127.0.0.1", "--port", "5173"],
            cwd=os.path.join(os.getcwd(), "frontend"),
        )
    except FileNotFoundError as error:
        raise RuntimeError(
            "npm is not installed or not available in PATH. Install Node.js and run `npm install` in the frontend/ folder."
        ) from error


if __name__ == "__main__":
    api_process = None
    frontend_process = None
    try:
        # Run L1 and capture the explicit output filename
        l1_out = run_l1()

        # run L2 explicitly using the L1 output
        l2_out = os.path.join(os.getcwd(), "l2_output1-6PP.jsonl")
        print_stage(2, 4, "Running L2 Layer")
        start = time.perf_counter()
        subprocess.run([
            sys.executable,
            "L2_processor.py",
            "--input",
            l1_out,
            "--output",
            l2_out,
            "--sample-size",
            "20000",
            "--min-severity",
            "MEDIUM",
            "--target-alerts",
            "30",
            "--verbose",
        ], check=True)
        elapsed = time.perf_counter() - start
        print(f"[L2] Completed in {elapsed:.1f}s")

        l3_db = os.path.join(os.getcwd(), "l3_context.db")
        l3_dataset = os.path.join(os.getcwd(), "sample_l3_incident_reports.json")
        l3_output = os.path.join(os.getcwd(), "L3_output")

        print_stage(3, 4, "Running L3 Agent and generating L3 output")
        start = time.perf_counter()
        subprocess.run([
            sys.executable,
            "L3_agent.py",
            "ingest",
            "--input",
            l2_out,
            "--db",
            l3_db,
            "--threshold",
            "7",
        ], check=True)
        subprocess.run([
            sys.executable,
            "L3_agent.py",
            "incident-report",
            "--db",
            l3_db,
            "--dataset",
            l3_dataset,
            "--out",
            l3_output,
        ], check=True)
        elapsed = time.perf_counter() - start
        print(f"[L3] Completed in {elapsed:.1f}s, output written to {l3_output}")

        api_process = start_api_server()
        frontend_process = start_frontend()

        print("\nPipeline complete. Open the dashboard at http://127.0.0.1:5173")
        print("Press Ctrl+C to stop the API server and frontend.")

        while True:
            if api_process.poll() is not None:
                print("API server stopped.")
                break
            if frontend_process.poll() is not None:
                print("Frontend process stopped.")
                break
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping pipeline...")
    except Exception as error:
        print("Pipeline failed:", error)
    finally:
        for proc in (api_process, frontend_process):
            if proc is not None and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
