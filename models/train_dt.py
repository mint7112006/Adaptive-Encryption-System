import os
import numpy as np
import pandas as pd
from sklearn.tree import DecisionTreeClassifier
import joblib

def build_and_save_decision_tree():
    # --------------------------------------------------------------------------
    # 1. TẬP DỮ LIỆU HUẤN LUYỆN DỰA TRÊN QUY TẮC MÃ HÓA THÍCH ỨNG
    # Feature 1: data_size_kb (float)
    # Feature 2: sensitivity_level (0: NON_SENSITIVE, 1: PII, 2: PIN, 3: CREDENTIALS)
    # Target Label: 0: 'NONE', 1: 'RSA-2048', 2: 'ChaCha20-Poly1305', 3: 'HYBRID_AES_RSA'
    # --------------------------------------------------------------------------
    
    X = [
        # [data_size_kb, sensitivity_level]
        [0.1, 0],   # 0: NONE
        [10.0, 0],  # 1: NONE
        [500.0, 0], # 2: NONE
        
        [0.5, 1],   # 3: PII nhỏ -> RSA-2048 (1)
        [1.0, 2],   # 4: PIN nhỏ -> RSA-2048 (1)
        [10.0, 1],  # 5: PII vừa -> ChaCha20-Poly1305 (2)
        [5.0, 1],   # 6: PII lớn (>5KB) -> HYBRID_AES_RSA (3)
        [100.0, 1], # 7: PII rất lớn (file 1000 dòng) -> HYBRID_AES_RSA (3)
        [100.0, 2], # 8: PIN lớn -> ChaCha20-Poly1305 (2)
        
        [0.2, 3],   # 9: CREDENTIALS nhỏ -> RSA-2048 (1)
        [2.0, 3],   # 10: CREDENTIALS > 2KB -> HYBRID_AES_RSA (3)
        [50.0, 3],  # 11: CREDENTIALS lớn -> HYBRID_AES_RSA (3)
        [500.0, 3]  # 12: CREDENTIALS cực lớn -> HYBRID_AES_RSA (3)
    ]
    
    y = [
        0, 0, 0,    # 3 mẫu đầu cho NONE
        1, 1,       # 2 mẫu tiếp theo cho RSA-2048
        2, 3, 3, 2, # 4 mẫu tiếp theo ứng với các dòng 5, 6, 7, 8 trong X
        1, 3, 3, 3  # 4 mẫu cuối ứng với các dòng 9, 10, 11, 12 trong X
    ]

    # Kiểm tra tính khớp số lượng mẫu (Đảm bảo đủ 13 mẫu)
    assert len(X) == len(y), f"Lỗi: Số lượng mẫu X ({len(X)}) không khớp với y ({len(y)})!"

    # 2. Huấn luyện mô hình Decision Tree
    clf = DecisionTreeClassifier(criterion='entropy', max_depth=5, random_state=42)
    clf.fit(X, y)

    # 3. Đảm bảo thư mục models/ tồn tại trước khi lưu
    output_dir = "models"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        
    model_path = os.path.join(output_dir, "decision_tree_model.pkl")
    joblib.dump(clf, model_path)
    print(f"[✓] Đã huấn luyện lại và lưu mô hình thành công vào: {model_path}")

if __name__ == "__main__":
    build_and_save_decision_tree()