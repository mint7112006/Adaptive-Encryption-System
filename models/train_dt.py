import os
import numpy as np
import pandas as pd
from sklearn.tree import DecisionTreeClassifier
import joblib

def build_and_save_decision_tree():
    # --------------------------------------------------------------------------
    # 1. TẬP DỮ LIỆU HUẤN LUYỆN CHỈ DỰA TRÊN ĐỘ NHẠY CẢM (SENSITIVITY LEVEL)
    # Feature: sensitivity_level (0: NON_SENSITIVE, 1: PII, 2: PIN, 3: CREDENTIALS)
    # Target Label: 0: 'NONE', 1: 'RSA-2048', 2: 'ChaCha20-Poly1305', 3: 'HYBRID_AES_RSA'
    # --------------------------------------------------------------------------
    
    X = [
        [0],  # 0: NON_SENSITIVE -> NONE (0)
        [1],  # 1: PII (CCCD, SĐT, Email) -> RSA-2048 (1)
        [2],  # 2: PIN -> ChaCha20-Poly1305 (2)
        [3]   # 3: CREDENTIALS (Password) -> HYBRID_AES_RSA (3)
    ]
    
    y = [
        0,  # NONE
        1,  # RSA-2048
        2,  # ChaCha20-Poly1305
        3   # HYBRID_AES_RSA
    ]

    # Kiểm tra tính khớp số lượng mẫu
    assert len(X) == len(y), f"Lỗi: Số lượng mẫu X ({len(X)}) không khớp với y ({len(y)})!"

    # 2. Huấn luyện mô hình Decision Tree (Vì chỉ có 1 feature, max_depth=2 là đủ)
    clf = DecisionTreeClassifier(criterion='entropy', max_depth=2, random_state=42)
    clf.fit(X, y)

    # 3. Đảm bảo thư mục models/ tồn tại trước khi lưu
    output_dir = "models"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        
    model_path = os.path.join(output_dir, "decision_tree_model.pkl")
    joblib.dump(clf, model_path)
    print(f"[✓] Đã huấn luyện lại và lưu mô hình tối ưu vào: {model_path}")

if __name__ == "__main__":
    build_and_save_decision_tree()