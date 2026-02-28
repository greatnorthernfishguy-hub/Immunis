#!/usr/bin/env bash
# Immunis Installer — E-T Systems Standard Pattern
# Creates directory structure, registers with ET Module Manager,
# and verifies vendored files.  Follows THC install.sh pattern.
set -euo pipefail

MODULE_ID="immunis"
ET_ROOT="$HOME/.et_modules"
MODULE_DIR="$ET_ROOT/$MODULE_ID"
INSTALL_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=== Immunis Installer ==="
echo "Install directory: $INSTALL_DIR"
echo ""

# 1. Create directory structure
echo "[1/5] Creating directory structure..."
mkdir -p "$MODULE_DIR"
mkdir -p "$MODULE_DIR/quarantine"
mkdir -p "$MODULE_DIR/forensics"
mkdir -p "$ET_ROOT/shared_learning"

# 2. Create default config.yaml if not present
echo "[2/5] Checking configuration..."
if [ ! -f "$MODULE_DIR/config.yaml" ]; then
    cp "$INSTALL_DIR/config.yaml" "$MODULE_DIR/config.yaml"
    echo "  Created default config.yaml"
else
    echo "  config.yaml already exists — keeping existing"
fi

# 3. Register with ET Module Manager
echo "[3/5] Registering with ET Module Manager..."
REGISTRY="$ET_ROOT/registry.json"
if [ ! -f "$REGISTRY" ]; then
    echo '{"modules": {}}' > "$REGISTRY"
fi
python3 -c "
import json, time
with open('$REGISTRY', 'r') as f:
    registry = json.load(f)
registry.setdefault('modules', {})
registry['modules']['$MODULE_ID'] = {
    'install_path': '$INSTALL_DIR',
    'registered_at': time.time(),
    'version': '0.1.0',
    'entry_point': 'immunis_hook.py',
}
with open('$REGISTRY', 'w') as f:
    json.dump(registry, f, indent=2)
print('  Registered as $MODULE_ID in', '$REGISTRY')
"

# 4. Create autonomic state file if not present
echo "[4/5] Checking autonomic state..."
AUTONOMIC="$ET_ROOT/autonomic_state.json"
if [ ! -f "$AUTONOMIC" ]; then
    python3 -c "
import json, time
state = {
    'state': 'PARASYMPATHETIC',
    'threat_level': 'none',
    'triggered_by': '',
    'timestamp': time.time(),
    'reason': 'default — initial installation',
}
with open('$AUTONOMIC', 'w') as f:
    json.dump(state, f, indent=2)
print('  Created autonomic_state.json')
"
else
    echo "  autonomic_state.json already exists — keeping existing"
fi

# 5. Verify vendored files
echo "[5/5] Verifying vendored files..."
VENDORED_FILES=("ng_lite.py" "ng_peer_bridge.py" "ng_ecosystem.py" "openclaw_adapter.py" "ng_autonomic.py")
ALL_PRESENT=true
for f in "${VENDORED_FILES[@]}"; do
    if [ -f "$INSTALL_DIR/$f" ]; then
        echo "  ✓ $f"
    else
        echo "  ✗ $f — MISSING"
        ALL_PRESENT=false
    fi
done

echo ""
echo "=== Installation Summary ==="
echo "Module ID:     $MODULE_ID"
echo "Install path:  $INSTALL_DIR"
echo "Data path:     $MODULE_DIR"
echo "Registry:      $REGISTRY"
if [ "$ALL_PRESENT" = true ]; then
    echo "Vendored files: All present"
else
    echo "Vendored files: INCOMPLETE — some files missing"
fi
echo ""
echo "Verify installation:"
echo "  python3 -c \"from immunis_hook import get_instance; print(get_instance().stats())\""
