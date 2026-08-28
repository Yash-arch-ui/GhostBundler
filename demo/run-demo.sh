#!/usr/bin/env bash
set -euo pipefail

# ── GhostBundler Demo Script ─────────────────────────────────────────
# Demonstrates the preflight policy analysis engine with two UserOps:
#   1. A SAFE operation  — owner calls a benign target → gets a permit
#   2. An UNSAFE operation — session key drains vault via global validation → blocked
#
# Prerequisites: anvil, forge, cargo (all in PATH)
# ──────────────────────────────────────────────────────────────────────

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEMO_DIR="$REPO_ROOT/demo"
EP_ADDR="0x5FbDB2315678afecb367f032d93F642f64180aa3"
ACCOUNT_ADDR="0xb044a63D8eD406bdAAD3Db50f79F2cbC1f734e10"
GHOSTD_PID=""

# ── Cleanup ───────────────────────────────────────────────────────────
cleanup() {
    if [ -n "$GHOSTD_PID" ] && kill -0 "$GHOSTD_PID" 2>/dev/null; then
        echo ">>> Stopping ghostd (pid $GHOSTD_PID)..."
        kill "$GHOSTD_PID" 2>/dev/null || true
        wait "$GHOSTD_PID" 2>/dev/null || true
    fi
    if [ "$ANVIL_WAS_RUNNING" = "false" ] && [ -n "${ANVIL_PID:-}" ]; then
        echo ">>> Stopping Anvil (pid $ANVIL_PID)..."
        kill "$ANVIL_PID" 2>/dev/null || true
        wait "$ANVIL_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

# ── Step 1: Ensure Anvil is running ──────────────────────────────────
ANVIL_WAS_RUNNING=false
ANVIL_PID=""
if curl -sf -X POST -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
    http://127.0.0.1:8545 >/dev/null 2>&1; then
    echo ">>> Anvil already running on :8545"
    ANVIL_WAS_RUNNING=true
else
    echo ">>> Starting Anvil on :8545..."
    anvil --silent --host 0.0.0.0 --port 8545 &
    ANVIL_PID=$!
    # Wait for Anvil to be ready
    for i in $(seq 1 30); do
        if curl -sf -X POST -H "Content-Type: application/json" \
            -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
            http://127.0.0.1:8545 >/dev/null 2>&1; then
            echo ">>> Anvil ready"
            break
        fi
        sleep 0.5
    done
fi

# ── Step 2: Deploy contracts if not already deployed ──────────────────
EP_CODE=$(curl -sf -X POST -H "Content-Type: application/json" \
    -d "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getCode\",\"params\":[\"$EP_ADDR\",\"latest\"],\"id\":1}" \
    http://127.0.0.1:8545 | python3 -c "import sys,json; r=json.load(sys.stdin); print(r.get('result','0x'))" 2>/dev/null || echo "0x")

if [ "$EP_CODE" = "0x" ] || [ ${#EP_CODE} -le 4 ]; then
    echo ">>> Contracts not deployed — running Deploy.s.sol..."
    cd "$REPO_ROOT/contracts"
    PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
        forge script script/Deploy.s.sol --broadcast --rpc-url http://127.0.0.1:8545
    cd "$REPO_ROOT"
    echo ">>> Deployment complete"
else
    echo ">>> Contracts already deployed at expected addresses"
fi

# ── Step 3: Build and start ghostd ───────────────────────────────────
echo ">>> Building ghostd..."
cargo build -p ghostd --quiet 2>&1

echo ">>> Starting ghostd on :3000..."
"$REPO_ROOT/target/debug/ghostd" &
GHOSTD_PID=$!

# Wait for ghostd to be ready
for i in $(seq 1 60); do
    if curl -sf http://127.0.0.1:3000 >/dev/null 2>&1 || \
       curl -sf -X POST http://127.0.0.1:3000/preflight -d '{}' >/dev/null 2>&1; then
        echo ">>> ghostd ready on :3000"
        break
    fi
    # Also try a TCP connect
    if (echo >/dev/tcp/127.0.0.1/3000) 2>/dev/null; then
        echo ">>> ghostd ready on :3000"
        break
    fi
    sleep 0.5
done

# Give it one more second for the server to fully bind
sleep 1

# ── Step 4: Send the SAFE UserOp ─────────────────────────────────────
echo ""
echo "══════════════════════════════════════════════════════════════"
echo "  SAFE USEROP — owner (isGlobal=false) calls benign target"
echo "══════════════════════════════════════════════════════════════"
echo ""
curl -s -X POST http://127.0.0.1:3000/preflight \
    -H "Content-Type: application/json" \
    -d @"$DEMO_DIR/safe.json" | python3 -m json.tool
echo ""

# ── Step 5: Send the UNSAFE UserOp ───────────────────────────────────
echo "══════════════════════════════════════════════════════════════"
echo "  UNSAFE USEROP — session key -> drain via global validation"
echo "══════════════════════════════════════════════════════════════"
echo ""
curl -s -X POST http://127.0.0.1:3000/preflight \
    -H "Content-Type: application/json" \
    -d @"$DEMO_DIR/privilege-escalation.json" | python3 -m json.tool
echo ""

echo ">>> Demo complete"
