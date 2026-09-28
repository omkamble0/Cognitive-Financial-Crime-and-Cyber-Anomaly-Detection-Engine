import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler


def load_data(path: str):
    df = pd.read_csv(path)
    return df


def preprocess(df: pd.DataFrame):
    # Kaggle dataset: Column v1...v28, Time, amount, class
    df = df.copy()
    # scale Amount and Time
    scaler = StandardScaler()
    df[['scaled_amount', 'scaled_time']] = scaler.fit_transform(df[['Amount', 'Time']])
    X = df.drop(columns=['Time', 'Amount', 'Class'])
    y = df['Class']
    return X, y, scaler


def split(X, y, test_size=0.2, random_state=42):
    return train_test_split(X, y, test_size=test_size, stratify=y, random_state=random_state)
