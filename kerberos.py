import os
import sys
import subprocess
import re
import pwn

pwn.context.log_level = "critical"

BANNER = r"""
 ____  __.          ___.                              

|    |/ _|__________\_ |__   ___________  ____  ______
|      <_/ __ \_  __ \ __ \_/ __ \_  __ \/  _ \/  ___/

|    |  \  ___/|  | \/ \_\ \  ___/|  | \(  <_> )___ \ 
|____|__ \___  >__|  |___  /\___  >__|   \____/____  >
        \/   \/          \/     \/                 \/ 
                 coded by 4B2A 
"""

def checksec(target):
    """Lite checksec implementation using ELF parsing."""
    try:
        elf = pwn.ELF(target, checksec=False)
        return {"NX": elf.nx, "PIE": elf.pie, "Arch": elf.arch, "Canary": elf.canary}
    except:
        return {"NX": False, "PIE": False, "Arch": "unknown", "Canary": False}

def detect_input_method(target):
    """Auto-detects if the binary expects input via STDIN or Arguments."""
    try:
        proc = subprocess.run([target], input=b"", capture_output=True, timeout=1.5)
        out = (proc.stderr + proc.stdout).decode("utf-8", errors="ignore").lower()
        if any(w in out for w in ["usage", "argv", "argument", "parameter", "option"]):
            return "argument"
    except subprocess.TimeoutExpired:
        pass
    return "stdin"

def run_gdb(target, payload, method):
    """Executes target inside GDB safely without shell expansion issues."""
    payload_file = os.path.abspath(".kerberos_payload.tmp")
    with open(payload_file, "wb") as f:
        f.write(payload)

    # Base GDB commands for stability
    gdb_commands = [
        "-batch",
        "-ex", "set disable-randomization on",
    ]

    if method == "argument":
        # Using GDB's internal python or command syntax to read file safely into arguments
        gdb_commands += [
            "-ex", f"python import sys; sys.argv = ['{target}']; open('{payload_file}', 'rb').read()" ,
            "-ex", f"run $(cat {payload_file})", # fall-back POSIX compliant
            "-ex", "info registers",
            "-ex", "x/gx $pc",
            target
        ]
        stdin_data = None
    else:
        gdb_commands += [
            "-ex", "run",
            "-ex", "info registers",
            "-ex", "x/gx $pc",
            target
        ]
        # Read from file or pipe directly to stdin inside subprocess
        stdin_data = payload

    try:
        proc = subprocess.run(
            ["gdb"] + gdb_commands, input=stdin_data, capture_output=True, timeout=8
        )
        output = proc.stdout.decode("utf-8", errors="ignore")
    finally:
        if os.path.exists(payload_file):
            os.remove(payload_file)

    return output

def analyze_crash(gdb_out, payload, sec_info):
    """Parses GDB registers, finds exact cyclical offsets, and scores exploitability."""
    print(f"\n{'=' * 20} KERBEROS REPORT {'=' * 20}")
    print(f"[*] Target Architecture: {sec_info['Arch'].upper()}")

    if not any(sig in gdb_out for sig in ["Segmentation fault", "SIGSEGV", "SIGBUS", "SIGILL"]):
        return print("[─] Result: NO CRASH DETECTED. (The binary handled the input smoothly.)")

    print("[💥] Result: CRASH DETECTED!")

    # Target specific register lines to prevent false-positives from other memory maps
    register_lines = re.findall(r'(?:rip|eip|rsp|esp|rbp|ebp|\$pc)\s+(0x[0-9a-fA-F]+)', gdb_out, re.IGNORECASE)
    
    # Fallback to general hex values if register lines parsing fails
    if not register_lines:
        register_lines = re.findall(r"0x[0-9a-fA-F]{8,16}", gdb_out)

    offset = None
    for hex_val in register_lines:
        try:
            val = int(hex_val, 16)
            for fmt in ["I", "Q"]:
                packed = pwn.p32(val) if fmt == "I" else pwn.p64(val)
                idx = pwn.cyclic_find(packed)
                if 0 <= idx < len(payload):
                    offset = idx
                    break
            if offset is not None:
                break
        except:
            continue

    # Exploitability Scoring Engine
    score, severity = 20, "LOW"
    reasons = ["Application crashed due to memory mismanagement."]

    if offset is not None:
        score += 40
        reasons.append(f"Direct control over a CPU register or pointer at exact offset: {offset}")
    if not sec_info["NX"]:
        score += 20
        reasons.append("NX (No-Execute) is disabled. Shellcode injection into stack is trivial.")
    if not sec_info["PIE"]:
        score += 20
        reasons.append("PIE is disabled. Code base addresses are static and predictable.")
    if sec_info.get("Canary") is False:
        score += 10
        reasons.append("Stack Canary is missing. Stack smashing mitigations are absent.")

    if score >= 80: severity = "CRITICAL"
    elif score >= 50: severity = "HIGH"
    elif score >= 30: severity = "MEDIUM"

    if offset is not None:
        print(f"[✓] Exploit Offset Found: Controlled at byte {offset}")
    print(f"[🔥] Exploitability Score: {score}/100 [{severity}]")
    for r in reasons:
        print(f"  └─> {r}")
    print("=" * 57)

def main():
    while True:
        os.system("clear" if os.name != "nt" else "cls")
        print(BANNER + "\n 1. Analyze Target Binary\n 2. Exit\n" + "-" * 55)
        choice = input(" Choice (1/2): ").strip()

        if choice == "1":
            target = input("\n[?] Enter target binary path (e.g., ./vuln): ").strip()
            if not os.path.exists(target):
                input("\n[!] Error: File not found! Press Enter...")
                continue

            if not os.access(target, os.X_OK):
                os.chmod(target, 0o755)

            sec_info = checksec(target)
            method = detect_input_method(target)
            print(f"[✓] Detection: Input method is {method.upper()}")

            payload = pwn.cyclic(5000)
            print("[*] Spawning GDB monitoring engine...")
            gdb_out = run_gdb(target, payload, method)

            analyze_crash(gdb_out, payload, sec_info)
            input("\nPress Enter to return to main menu...")
        elif choice == "2":
            sys.exit(0)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
