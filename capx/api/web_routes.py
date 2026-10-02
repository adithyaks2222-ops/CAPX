from flask import Blueprint, jsonify, render_template
from capx.api.inspector import InspectEngine
from capx.logging_config import logger

web_bp = Blueprint('web', __name__)
engine = InspectEngine()

@web_bp.route('/')
def dashboard():
    """Renders the main CAPX dashboard interface."""
    return render_template('index.html')

@web_bp.route('/api/scan', methods=['GET'])
def api_scan():
    """Executes the inspection engine and returns raw JSON data to the UI."""
    logger.info("Web UI triggered a full system scan...")
    try:
        results = engine.run_full_inspection()
        return jsonify({"status": "success", "data": results})
    except Exception as e:
        logger.error(f"Scan failed via Web UI: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500