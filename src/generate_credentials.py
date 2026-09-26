
import secrets
import os
import pandas as pd
import time
import string

def generate_random_password(length):
    """Sinh mật khẩu ngẫu nhiên an toàn gồm chữ hoa, chữ thường, số và ký tự đặc biệt"""
    characters = string.ascii_letters + string.digits + "!@#$%^&*()_+-={}[]:;<>?/~"
    return ''.join(secrets.choice(characters) for _ in range(length))
#################################################################################
def generate_random_pin(length):
    """Sinh mã PIN ngẫu nhiên dạng chuỗi số (4 hoặc 6 chữ số)"""
    return ''.join(secrets.choice(string.digits) for _ in range(length))
#################################################################################
def generate_pii_dataset(num_records):
    data = []
    
    for i in range(1, num_records + 1):
        record = { 
            "Stt": i,
            "Mật khẩu": generate_random_password(secrets.choice(range(16,20))) ,
            "Mã PIN":  generate_random_pin(secrets.choice([4, 6]))
        }
        data.append(record)
    
    df = pd.DataFrame(data)
    
    output_dir = './input_data'
    os.makedirs(output_dir, exist_ok=True)
    
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    output_filename = f"credentials_{timestamp}.csv"
    output_path = os.path.join(output_dir, output_filename)
    df.to_csv(output_path, index=False, encoding='utf-8-sig')


if __name__ == "__main__":
    generate_pii_dataset(10)