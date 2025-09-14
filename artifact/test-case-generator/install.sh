#!/bin/bash

# OTABase - Setup and run script
set -e

# Setup virtual environment if it doesn't exist
if [ ! -d "otabase_venv" ]; then
    echo "Setting up OTABase environment..."
    python3 -m venv otabase_venv
    source otabase_venv/bin/activate
    pip install -r requirements.txt
    echo "Setup complete."
else
    echo "Activating OTABase environment..."
    source otabase_venv/bin/activate
fi