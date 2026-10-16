"""
Preprocessor Module
Handles categorical encoding, feature scaling, train/test splitting,
and serializes preprocessing pipelines for production inference.
"""

import os
import joblib
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler


class CyberDataPreprocessor:
    def __init__(self):
        self.scaler = StandardScaler()
        self.categorical_cols = ["protocol_type", "service"]
        self.numeric_cols = [
            "duration", "src_bytes", "dst_bytes", "failed_logins",
            "logged_in", "count", "srv_count", "serror_rate",
            "rerror_rate", "same_srv_rate", "diff_srv_rate",
            "dst_host_count", "dst_host_srv_count"
        ]
        self.feature_columns = None
        self.fitted = False

    def clean_data(self, df: pd.DataFrame) -> pd.DataFrame:
        """Removes duplicates, handles null values and cleans anomalies."""
        data = df.copy()
        data = data.drop_duplicates()
        data = data.ffill().bfill()
        return data

    def fit_transform(self, df: pd.DataFrame):
        """Fits scaler and encoders on training data and returns processed features and labels."""
        data = self.clean_data(df)
        
        # Binary target: is_threat (0: Normal, 1: Threat)
        y_binary = data["is_threat"].values
        y_multiclass = data["attack_type"].values if "attack_type" in data.columns else None

        # Feature matrix preparation
        X_cat = pd.get_dummies(data[self.categorical_cols], drop_first=False)
        X_num = pd.DataFrame(
            self.scaler.fit_transform(data[self.numeric_cols]),
            columns=self.numeric_cols,
            index=data.index
        )
        
        X_processed = pd.concat([X_num, X_cat], axis=1)
        self.feature_columns = list(X_processed.columns)
        self.fitted = True

        return X_processed, y_binary, y_multiclass

    def transform_single_record(self, record_dict: dict) -> pd.DataFrame:
        """Transforms a single incoming network packet/log for real-time inference."""
        if not self.fitted:
            raise RuntimeError("Preprocessor has not been fitted or loaded yet.")

        # Ensure all expected numeric features exist
        for col in self.numeric_cols:
            if col not in record_dict:
                record_dict[col] = 0

        df_single = pd.DataFrame([record_dict])
        
        # Scale numeric features
        X_num = pd.DataFrame(
            self.scaler.transform(df_single[self.numeric_cols]),
            columns=self.numeric_cols
        )
        
        # One-hot encode categoricals matching fitted structure
        X_cat = pd.get_dummies(df_single[self.categorical_cols], drop_first=False)
        
        # Realign to match exact training columns
        X_combined = pd.concat([X_num, X_cat], axis=1)
        X_aligned = pd.DataFrame(0.0, index=[0], columns=self.feature_columns)
        
        for col in X_combined.columns:
            if col in self.feature_columns:
                X_aligned[col] = X_combined[col].values[0]
                
        return X_aligned

    def save(self, filepath: str = "models/preprocessor.pkl"):
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        joblib.dump(self, filepath)
        print(f"[+] Preprocessor saved to {filepath}")

    @staticmethod
    def load(filepath: str = "models/preprocessor.pkl"):
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"No preprocessor file found at {filepath}")
        return joblib.load(filepath)


def prepare_train_test_data(data_path: str = "data/raw/sample_network_traffic.csv"):
    """Reads raw data, applies preprocessing, splits into train/test, and persists processed files."""
    df = pd.read_csv(data_path)
    preprocessor = CyberDataPreprocessor()
    
    X, y_bin, y_multi = preprocessor.fit_transform(df)
    
    X_train, X_test, y_train, y_test, multi_train, multi_test = train_test_split(
        X, y_bin, y_multi, test_size=0.20, random_state=42, stratify=y_bin
    )
    
    os.makedirs("data/processed", exist_ok=True)
    train_df = X_train.copy()
    train_df["is_threat"] = y_train
    train_df["attack_type"] = multi_train
    train_df.to_csv("data/processed/train.csv", index=False)

    test_df = X_test.copy()
    test_df["is_threat"] = y_test
    test_df["attack_type"] = multi_test
    test_df.to_csv("data/processed/test.csv", index=False)

    preprocessor.save("models/preprocessor.pkl")
    print(f"[+] Processed datasets saved: Train shape {X_train.shape}, Test shape {X_test.shape}")
    return X_train, X_test, y_train, y_test, multi_train, multi_test, preprocessor


if __name__ == "__main__":
    prepare_train_test_data()
