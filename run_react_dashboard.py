import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parent
FRONTEND_DIR = ROOT / "frontend"


def run_l1():
    print("\nRunning L1 Layer...")
    subprocess.run(["python", "L1.balanced.py"], check=True, cwd=ROOT)


def run_l2():
    print("\nRunning L2 Layer...")
    subprocess.run(["python", "L2_processor.py"], check=True, cwd=ROOT)


def run_api():
    print("\nStarting Python API on http://127.0.0.1:8000 ...")
    return subprocess.Popen(["python", "api_server.py"], cwd=ROOT)


def run_frontend():
    print("\nStarting React dashboard on http://127.0.0.1:5173 ...")
    return subprocess.Popen(["npm.cmd", "run", "dev"], cwd=FRONTEND_DIR)


if __name__ == "__main__":
    api_process = None
    frontend_process = None

    try:
        run_l1()
        run_l2()
        api_process = run_api()
        frontend_process = run_frontend()

        print("\nReact dashboard stack is starting.")
        print("API: http://127.0.0.1:8000/api/alerts")
        print("UI:  http://127.0.0.1:5173")

        if frontend_process:
            frontend_process.wait()
    except KeyboardInterrupt:
        print("\nStopping dashboard stack...")
    except Exception as error:
        print("Dashboard stack failed:", error)
    finally:
        if frontend_process and frontend_process.poll() is None:
            frontend_process.terminate()
        if api_process and api_process.poll() is None:
            api_process.terminate()
