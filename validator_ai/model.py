import os
import hashlib
import threading
import logging
import numpy as np
import tensorflow.lite as tflite
from typing import Optional, Dict, Tuple

logger = logging.getLogger(__name__)
MODEL_DIR = os.path.join(os.path.dirname(__file__), 'dataset')

# Predefined SHA256 checksums for trusted models
KNOWN_MODELS = {
    'tx_validator.tflite': 'a9c1f3...your_hash_here...',
    'fraud_detector.tflite': '8a2d14...your_hash_here...',
    'reputation_model.tflite': 'b7f3ca...your_hash_here...'
}

class ModelLoadError(Exception):
    pass

class ModelManager:
    """
    Manage .tflite models used by the AI validator.
    - Verifies model integrity using SHA256.
    - Supports multiple models.
    - Thread-safe caching for reuse.
    """
    _models: Dict[str, tflite.Interpreter] = {}
    _model_locks: Dict[str, threading.RLock] = {}
    _global_lock = threading.RLock()

    @staticmethod
    def _validate_model_checksum(path: str, expected_hash: str) -> bool:
        sha256 = hashlib.sha256()
        with open(path, 'rb') as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                sha256.update(chunk)
        actual_hash = sha256.hexdigest()
        return actual_hash == expected_hash

    @classmethod
    def load_model(cls, model_name: str) -> tflite.Interpreter:
        with cls._global_lock:
            if model_name in cls._models:
                return cls._models[model_name]

            model_path = os.path.join(MODEL_DIR, model_name)

            if not os.path.exists(model_path):
                raise ModelLoadError(f"Model file not found: {model_path}")

            if model_name in KNOWN_MODELS:
                expected_hash = KNOWN_MODELS[model_name]
                if not cls._validate_model_checksum(model_path, expected_hash):
                    raise ModelLoadError(f"Model checksum mismatch for: {model_name}")
            else:
                logger.warning(f"Model {model_name} not found in KNOWN_MODELS. Skipping integrity check.")

            try:
                interpreter = tflite.Interpreter(model_path=model_path)
                interpreter.allocate_tensors()
                cls._models[model_name] = interpreter
                cls._model_locks[model_name] = threading.RLock()
                logger.info(f"Successfully loaded model: {model_name}")
                return interpreter
            except Exception as e:
                logger.error(f"Failed to load model {model_name}: {str(e)}")
                raise ModelLoadError(f"Failed to initialize interpreter: {str(e)}")

    @classmethod
    def get_model_lock(cls, model_name: str) -> threading.RLock:
        with cls._global_lock:
            return cls._model_locks.get(model_name, threading.RLock())

    @classmethod
    def predict(cls, model_name: str, input_data: np.ndarray) -> Optional[np.ndarray]:
        try:
            interpreter = cls.load_model(model_name)
            lock = cls.get_model_lock(model_name)

            with lock:
                input_details = interpreter.get_input_details()
                output_details = interpreter.get_output_details()

                interpreter.set_tensor(input_details[0]['index'], input_data.astype(np.float32))
                interpreter.invoke()
                output = interpreter.get_tensor(output_details[0]['index'])
                return output

        except ModelLoadError as e:
            logger.error(f"Prediction aborted: {str(e)}")
            return None

        except Exception as e:
            logger.exception(f"Unexpected error during prediction: {str(e)}")
            return None
