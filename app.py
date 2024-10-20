from flask import Flask, request, jsonify, render_template, send_from_directory
import os
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64
from Blockchain import Blockchain
from Block import Block
import logging
import tempfile
from datetime import datetime
import traceback

app = Flask(__name__, 
    static_folder='static',
    template_folder='templates')

UPLOAD_FOLDER = 'data'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'csv', 'json'}
MAX_FILE_SIZE = 16 * 1024 * 1024  # 16MB max file size

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE
blockchain = Blockchain()

# Enhanced logging configuration
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('blockchain.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Generate a secure key and save it (in a production environment, use proper key management)
def get_or_create_key():
    key_file = 'encryption.key'
    if os.path.exists(key_file):
        with open(key_file, 'rb') as f:
            return f.read()
    else:
        key = get_random_bytes(32)  # 256-bit key
        with open(key_file, 'wb') as f:
            f.write(key)
        return key

# Initialize encryption key
key = get_or_create_key()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def secure_filename(filename):
    """Sanitize filename"""
    return ''.join(c for c in filename if c.isalnum() or c in '._-')

def read_file_content(file_path, original_filename):
    """Enhanced file reading with better error handling"""
    try:
        # Determine how to read the file based on its extension
        ext = original_filename.rsplit('.', 1)[1].lower() if '.' in original_filename else ''
        
        if ext in ['txt', 'csv', 'json']:
            # Text file handling
            with open(file_path, 'r', encoding='utf-8') as f:
                return f.read()
        else:
            # Binary file handling
            with open(file_path, 'rb') as f:
                return base64.b64encode(f.read()).decode('utf-8')
                
    except UnicodeDecodeError:
        # Fallback to binary reading if text reading fails
        with open(file_path, 'rb') as f:
            return base64.b64encode(f.read()).decode('utf-8')
    except Exception as e:
        logger.error(f"Error reading file {original_filename}: {str(e)}")
        raise

def encrypt_data(data_dict):
    """Encrypt data with improved error handling"""
    try:
        # Convert dictionary to JSON string
        json_data = json.dumps(data_dict)
        
        # Generate a random IV
        iv = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        # Pad and encrypt the data
        padded_data = pad(json_data.encode(), AES.block_size)
        encrypted_data = cipher.encrypt(padded_data)
        
        # Combine IV and encrypted data
        combined_data = iv + encrypted_data
        
        # Encode to base64 for storage
        return base64.b64encode(combined_data).decode('utf-8')
    
    except Exception as e:
        logger.error(f"Encryption error: {str(e)}")
        raise

def decrypt_data(encrypted_data):
    """Decrypt data with improved error handling"""
    try:
        # Decode from base64
        combined_data = base64.b64decode(encrypted_data)
        
        # Extract IV and ciphertext
        iv = combined_data[:16]
        ciphertext = combined_data[16:]
        
        # Create cipher and decrypt
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_data = cipher.decrypt(ciphertext)
        
        # Unpad and decode
        data = unpad(padded_data, AES.block_size)
        return json.loads(data.decode())
    
    except Exception as e:
        logger.error(f"Decryption error: {str(e)}")
        raise

@app.route("/new_transaction", methods=["POST"])
def new_transaction():
    logger.info("Starting new transaction processing")
    
    try:
        # Validate request
        if 'data_file' not in request.files:
            logger.warning("No file part in request")
            return jsonify({"error": "No file provided"}), 400
        
        file = request.files['data_file']
        user = request.form.get('user')

        # Log transaction attempt
        logger.info(f"Processing transaction for user: {user}, file: {file.filename}")

        # Validate user
        if not user:
            return jsonify({"error": "User ID is required"}), 400

        # Validate file
        if file.filename == '':
            return jsonify({"error": "No selected file"}), 400

        if not allowed_file(file.filename):
            logger.warning(f"Invalid file type attempted: {file.filename}")
            return jsonify({"error": f"File type not allowed. Allowed types are: {', '.join(ALLOWED_EXTENSIONS)}"}), 400

        # Create temporary file
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            try:
                # Save uploaded file to temp location
                file.save(temp_file.name)
                logger.debug(f"File temporarily saved as: {temp_file.name}")
                
                # Check file size
                file_size = os.path.getsize(temp_file.name)
                if file_size > MAX_FILE_SIZE:
                    raise ValueError(f"File size ({file_size} bytes) exceeds maximum limit ({MAX_FILE_SIZE} bytes)")

                # Read file content
                data_content = read_file_content(temp_file.name, file.filename)
                
                # Prepare transaction data
                transaction_data = {
                    "user": user,
                    "filename": secure_filename(file.filename),
                    "data_type": file.content_type,
                    "data_content": data_content,
                    "data_size": file_size,
                    "timestamp": datetime.now().isoformat(),
                    "transaction_id": base64.b64encode(get_random_bytes(8)).decode('utf-8')
                }

                # Encrypt and add to blockchain
                encrypted_data = encrypt_data(transaction_data)
                blockchain.add_pending(encrypted_data)

                logger.info(f"Transaction processed successfully. ID: {transaction_data['transaction_id']}")

                return jsonify({
                    "message": "Transaction added successfully",
                    "transaction_id": transaction_data['transaction_id'],
                    "file_size": file_size
                }), 201

            except Exception as e:
                error_details = traceback.format_exc()
                logger.error(f"Error processing transaction: {str(e)}\n{error_details}")
                return jsonify({
                    "error": "Transaction processing failed",
                    "details": str(e)
                }), 500
            finally:
                # Clean up temporary file
                try:
                    os.unlink(temp_file.name)
                    logger.debug("Temporary file cleaned up")
                except Exception as e:
                    logger.error(f"Error removing temporary file: {str(e)}")

    except Exception as e:
        error_details = traceback.format_exc()
        logger.error(f"Unexpected error in transaction processing: {str(e)}\n{error_details}")
        return jsonify({
            "error": "Transaction failed",
            "details": str(e)
        }), 500

@app.route("/chain", methods=["GET"])
def get_chain():
    try:
        chain_data = []
        for block in blockchain.chain:
            block_transactions = []
            for tx in block.transactions:
                try:
                    decrypted_tx = decrypt_data(tx)
                    # Remove the large data_content field for display
                    if 'data_content' in decrypted_tx:
                        decrypted_tx['data_content'] = f"<{len(decrypted_tx['data_content'])} bytes>"
                    block_transactions.append(decrypted_tx)
                except Exception as e:
                    logger.error(f"Error decrypting transaction: {str(e)}")
                    block_transactions.append({"error": "Decryption failed", "raw": tx[:100] + "..."})

            block_dict = {
                "index": block.index,
                "transactions": block_transactions,
                "prev_hash": block.prev_hash,
                "nonce": block.nonce,
                "hash": getattr(block, 'hash', None)
            }
            chain_data.append(block_dict)
        
        return jsonify({
            "chain": chain_data,
            "length": len(chain_data)
        }), 200
    except Exception as e:
        logger.error(f"Error retrieving chain: {str(e)}")
        return jsonify({
            "error": "Failed to retrieve chain",
            "details": str(e)
        }), 500

# Update the mining endpoint to handle errors better
@app.route("/mine", methods=["GET"])
def mine_unconfirmed_transactions():
    try:
        logger.info("Starting mining process")
        result = blockchain.mine()
        
        if result:
            logger.info(f"Successfully mined block #{result}")
            return jsonify({
                "message": f"Block #{result} mined successfully",
                "block_index": result
            }), 200
        
        logger.info("No pending transactions to mine")
        return jsonify({
            "message": "No pending transactions to mine"
        }), 200
        
    except Exception as e:
        error_details = traceback.format_exc()
        logger.error(f"Mining error: {str(e)}\n{error_details}")
        return jsonify({
            "error": "Mining failed",
            "details": str(e)
        }), 500

if __name__ == '__main__':
    # Create required directories
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    
    # Add startup logging
    logger.info("Starting blockchain application")
    logger.info(f"Upload folder: {UPLOAD_FOLDER}")
    logger.info(f"Allowed extensions: {ALLOWED_EXTENSIONS}")
    
    app.run(port=8800, debug=True)