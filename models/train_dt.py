import numpy as np
import pandas as pd
from sklearn.tree import DecisionTreeClassifier
import joblib

def build_and_save_decision_tree():
    # --------------------------------------------------------------------------
    # 1. TẠO TẬP DỮ LIỆU HUẤN LUYỆN DỰA TRÊN QUY TẮC MÃ HÓA THÍCH ỨNG
    # Feature 1: data_size_kb (float)
    # Feature 2: sensitivity_level (0: NON_SENSITIVE, 1: PII, 2: PIN, 3: CREDENTIALS)
    # Target Label: 0: 'NONE', 1: 'RSA-2048', 2: 'ChaCha20-Poly1305', 3: 'HYBRID_AES_RSA'
    # --------------------------------------------------------------------------
    
    X = [
        # [data_size_kb, sensitivity_level]
        # Level 0: Không nhạy cảm -> Không mã hóa / Dạng rõ
        [0.1, 0], [10.0, 0], [500.0, 0],
        
        # Level 1 (PII) / Level 2 (PIN): Dữ liệu nhỏ -> RSA; Dữ liệu lớn -> ChaCha20
        [0.5, 1],   # PII nhỏ -> RSA-2048
        [1.0, 2],   # PIN nhỏ -> RSA-2048
        [10.0, 1],  # PII vừa/lớn -> ChaCha20-Poly1305
        [100.0, 2], # PIN lớn -> ChaCha20-Poly1305
        
        # Level 3 (CREDENTIALS / Rất nhạy cảm): 
        # Dữ liệu nhỏ -> RSA-2048; Dữ liệu lớn/file -> HYBRID (AES-256 + RSA)
        [0.2, 3],   # Mật khẩu đơn lẻ -> RSA-2048
        [2.0, 3],   # File/Dòng chứa CREDENTIALS > 2KB -> HYBRID_AES_RSA
        [50.0, 3],  # File nhạy cảm lớn -> HYBRID_AES_RSA
        [500.0, 3]  # File cực lớn -> HYBRID_AES_RSA
    ]
    
    y = [
        0, 0, 0,    # 'NONE'
        1, 1,       # 'RSA-2048'
        2, 2,       # 'ChaCha20-Poly1305'
        1, 3, 3, 3  # 'RSA-2048' & 'HYBRID_AES_RSA'
    ]

    # 2. Huấn luyện mô hình Decision Tree
    clf = DecisionTreeClassifier(criterion='entropy', max_depth=4, random_state=42)
    clf.fit(X, y)

    # 3. Lưu mô hình ra file .pkl
    model_filename = "decision_tree_model.pkl"
    joblib.dump(clf, model_filename)
    print(f"[✓] Đã lưu mô hình Decision Tree thành công vào: {model_filename}")

if __name__ == "__main__":
    build_and_save_decision_tree()