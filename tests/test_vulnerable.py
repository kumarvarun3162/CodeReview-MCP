import pickle
import os

password = "super_secret_123"
api_key = "sk-abc123realkey"

def process_input(user_data):
    result = eval(user_data)
    return result

def run_command(cmd):
    os.system(cmd)

def load_data(data):
    return pickle.loads(data)

def divide(a, b):
    try:
        return a / b
    except:
        return 0



