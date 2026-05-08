import pickle
import os

# Hardcoded secret - will be caught by AST scanner
api_key = "sk-abc123realapikey456"
db_password = "admin123"

def process_user_input(user_data):
    # eval() - critical vulnerability
    result = eval(user_data)
    return result

def run_system_command(cmd):
    # os.system - high vulnerability  
    os.system(cmd)

def deserialize(data):
    # pickle.loads - critical vulnerability
    return pickle.loads(data)

def divide_numbers(a, b):
    # bare except - caught by AST
    try:
        return a / b
    except:
        return 0