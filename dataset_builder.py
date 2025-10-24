"""
SDN-DDoS Dataset Builder and Preprocessor
Aggregates CSV files, cleans data, and prepares for ML training
"""

import pandas as pd
import numpy as np
import glob
import os
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

class DatasetBuilder:
    """Build and preprocess SDN-DDoS dataset"""
    
    def __init__(self, csv_pattern='sdn_ddos_dataset_*.csv'):
        self.csv_pattern = csv_pattern
        self.dataset = None
        self.feature_columns = None
        self.scaler = StandardScaler()
        
    def aggregate_csv_files(self):
        """Aggregate all CSV files matching the pattern"""
        print("Aggregating CSV files...")
        
        csv_files = glob.glob(self.csv_pattern)
        
        if not csv_files:
            raise FileNotFoundError(f"No CSV files found matching pattern: {self.csv_pattern}")
        
        print(f"Found {len(csv_files)} CSV files")
        
        dfs = []
        for i, csv_file in enumerate(csv_files, 1):
            print(f"  [{i}/{len(csv_files)}] Loading {csv_file}...")
            try:
                df = pd.read_csv(csv_file)
                dfs.append(df)
                print(f"      Loaded {len(df)} rows")
            except Exception as e:
                print(f"      Error loading {csv_file}: {e}")
        
        if not dfs:
            raise ValueError("No data loaded from CSV files")
        
        # Concatenate all dataframes
        self.dataset = pd.concat(dfs, ignore_index=True)
        print(f"\nTotal rows aggregated: {len(self.dataset)}")
        print(f"Columns: {list(self.dataset.columns)}")
        
        return self.dataset
    
    def clean_data(self):
        """Clean and preprocess the dataset"""
        print("\nCleaning data...")
        
        if self.dataset is None:
            raise ValueError("No dataset loaded. Run aggregate_csv_files() first.")
        
        initial_rows = len(self.dataset)
        
        # Remove duplicates
        self.dataset.drop_duplicates(inplace=True)
        print(f"  Removed {initial_rows - len(self.dataset)} duplicate rows")
        
        # Handle missing values
        missing = self.dataset.isnull().sum()
        if missing.any():
            print(f"  Missing values found:")
            print(missing[missing > 0])
            self.dataset.fillna(0, inplace=True)
            print(f"  Filled missing values with 0")
        
        # Remove invalid flows (e.g., zero packet count)
        invalid_mask = (self.dataset['packet_count'] == 0) | (self.dataset['byte_count'] == 0)
        self.dataset = self.dataset[~invalid_mask]
        print(f"  Removed {invalid_mask.sum()} invalid flows")
        
        # Handle infinite values
        self.dataset.replace([np.inf, -np.inf], 0, inplace=True)
        
        # Convert IP addresses to numeric (if needed for some models)
        if 'src_ip' in self.dataset.columns:
            self.dataset['src_ip_numeric'] = self.dataset['src_ip'].apply(self._ip_to_int)
        if 'dst_ip' in self.dataset.columns:
            self.dataset['dst_ip_numeric'] = self.dataset['dst_ip'].apply(self._ip_to_int)
        
        print(f"  Final dataset size: {len(self.dataset)} rows")
        
        return self.dataset
    
    def _ip_to_int(self, ip_str):
        """Convert IP address to integer"""
        try:
            if ip_str == '0.0.0.0' or not isinstance(ip_str, str):
                return 0
            parts = ip_str.split('.')
            return (int(parts[0]) << 24) + (int(parts[1]) << 16) + \
                   (int(parts[2]) << 8) + int(parts[3])
        except:
            return 0
    
    def feature_engineering(self):
        """Create additional features"""
        print("\nEngineering features...")
        
        if self.dataset is None:
            raise ValueError("No dataset loaded.")
        
        # Flow-based features
        self.dataset['packets_per_second'] = \
            self.dataset['packet_count'] / (self.dataset['flow_duration'] + 1e-6)
        
        self.dataset['bytes_per_second'] = \
            self.dataset['byte_count'] / (self.dataset['flow_duration'] + 1e-6)
        
        self.dataset['bytes_per_packet_ratio'] = \
            self.dataset['byte_count'] / (self.dataset['packet_count'] + 1)
        
        # Protocol flags
        self.dataset['is_tcp'] = (self.dataset['protocol'] == 6).astype(int)
        self.dataset['is_udp'] = (self.dataset['protocol'] == 17).astype(int)
        self.dataset['is_icmp'] = (self.dataset['protocol'] == 1).astype(int)
        
        # Port-based features
        self.dataset['is_well_known_port'] = \
            ((self.dataset['dst_port'] > 0) & (self.dataset['dst_port'] <= 1024)).astype(int)
        
        print(f"  Added engineered features")
        print(f"  Total features: {len(self.dataset.columns)}")
        
        return self.dataset
    
    def get_feature_columns(self, exclude_cols=None):
        """Get list of feature columns for ML"""
        if exclude_cols is None:
            exclude_cols = ['timestamp', 'datapath_id', 'flow_id', 
                          'src_ip', 'dst_ip', 'label']
        
        self.feature_columns = [col for col in self.dataset.columns 
                               if col not in exclude_cols]
        
        return self.feature_columns
    
    def prepare_ml_data(self, test_size=0.2, random_state=42):
        """Prepare data for machine learning"""
        print("\nPreparing data for ML...")
        
        if self.dataset is None or self.feature_columns is None:
            raise ValueError("Dataset not ready. Run clean_data() and get_feature_columns() first.")
        
        # Separate features and labels
        X = self.dataset[self.feature_columns].copy()
        y = self.dataset['label'].copy()
        
        # Handle any remaining non-numeric columns
        for col in X.columns:
            if X[col].dtype == 'object':
                le = LabelEncoder()
                X[col] = le.fit_transform(X[col].astype(str))
        
        print(f"  Features shape: {X.shape}")
        print(f"  Labels shape: {y.shape}")
        
        # Check class distribution
        print(f"\n  Class distribution:")
        print(f"    Normal (0): {(y == 0).sum()} ({(y == 0).sum()/len(y)*100:.2f}%)")
        print(f"    DDoS (1): {(y == 1).sum()} ({(y == 1).sum()/len(y)*100:.2f}%)")
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=random_state, stratify=y
        )
        
        print(f"\n  Train set: {len(X_train)} samples")
        print(f"  Test set: {len(X_test)} samples")
        
        # Normalize features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Convert back to DataFrame for easier handling
        X_train_scaled = pd.DataFrame(X_train_scaled, columns=X.columns)
        X_test_scaled = pd.DataFrame(X_test_scaled, columns=X.columns)
        
        return X_train_scaled, X_test_scaled, y_train, y_test
    
    def save_processed_dataset(self, filename='sdn_ddos_processed.csv'):
        """Save the complete processed dataset"""
        print(f"\nSaving processed dataset to {filename}...")
        
        if self.dataset is None:
            raise ValueError("No dataset to save.")
        
        self.dataset.to_csv(filename, index=False)
        print(f"  Saved {len(self.dataset)} rows")
        
        return filename
    
    def save_train_test_split(self, X_train, X_test, y_train, y_test,
                             prefix='sdn_ddos'):
        """Save train and test sets separately"""
        print("\nSaving train/test splits...")
        
        # Save training data
        train_df = X_train.copy()
        train_df['label'] = y_train.values
        train_file = f'{prefix}_train.csv'
        train_df.to_csv(train_file, index=False)
        print(f"  Saved {train_file} ({len(train_df)} rows)")
        
        # Save test data
        test_df = X_test.copy()
        test_df['label'] = y_test.values
        test_file = f'{prefix}_test.csv'
        test_df.to_csv(test_file, index=False)
        print(f"  Saved {test_file} ({len(test_df)} rows)")
        
        return train_file, test_file
    
    def generate_statistics(self):
        """Generate dataset statistics"""
        print("\n" + "="*60)
        print("DATASET STATISTICS")
        print("="*60)
        
        if self.dataset is None:
            print("No dataset loaded.")
            return
        
        print(f"\nDataset Shape: {self.dataset.shape}")
        print(f"  Rows: {len(self.dataset)}")
        print(f"  Columns: {len(self.dataset.columns)}")
        
        print("\nClass Distribution:")
        class_counts = self.dataset['label'].value_counts()
        for label, count in class_counts.items():
            label_name = "Normal" if label == 0 else "DDoS"
            print(f"  {label_name} ({label}): {count} ({count/len(self.dataset)*100:.2f}%)")
        
        print("\nNumerical Feature Statistics:")
        numeric_cols = self.dataset.select_dtypes(include=[np.number]).columns
        stats = self.dataset[numeric_cols].describe()
        print(stats)
        
        print("\nProtocol Distribution:")
        if 'protocol' in self.dataset.columns:
            protocol_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
            protocol_counts = self.dataset['protocol'].value_counts()
            for proto, count in protocol_counts.items():
                proto_name = protocol_map.get(proto, f'Other({proto})')
                print(f"  {proto_name}: {count} ({count/len(self.dataset)*100:.2f}%)")
        
        print("\n" + "="*60)


def main():
    """Main execution function"""
    print("\n" + "="*60)
    print("SDN-DDoS DATASET BUILDER")
    print("="*60 + "\n")
    
    # Initialize builder
    builder = DatasetBuilder(csv_pattern='sdn_ddos_dataset_*.csv')
    
    try:
        # Step 1: Aggregate CSV files
        print("STEP 1: Aggregating CSV files")
        print("-" * 60)
        dataset = builder.aggregate_csv_files()
        
        # Step 2: Clean data
        print("\nSTEP 2: Cleaning data")
        print("-" * 60)
        dataset = builder.clean_data()
        
        # Step 3: Feature engineering
        print("\nSTEP 3: Feature engineering")
        print("-" * 60)
        dataset = builder.feature_engineering()
        
        # Step 4: Get feature columns
        print("\nSTEP 4: Selecting features")
        print("-" * 60)
        features = builder.get_feature_columns()
        print(f"Selected {len(features)} features:")
        for i, feat in enumerate(features, 1):
            print(f"  {i:2d}. {feat}")
        
        # Step 5: Prepare ML data
        print("\nSTEP 5: Preparing ML datasets")
        print("-" * 60)
        X_train, X_test, y_train, y_test = builder.prepare_ml_data(
            test_size=0.2, random_state=42
        )
        
        # Step 6: Save datasets
        print("\nSTEP 6: Saving datasets")
        print("-" * 60)
        
        # Save complete processed dataset
        builder.save_processed_dataset('sdn_ddos_complete.csv')
        
        # Save train/test splits
        builder.save_train_test_split(X_train, X_test, y_train, y_test,
                                     prefix='sdn_ddos')
        
        # Step 7: Generate statistics
        print("\nSTEP 7: Generating statistics")
        print("-" * 60)
        builder.generate_statistics()
        
        print("\n" + "="*60)
        print("DATASET BUILDING COMPLETE!")
        print("="*60)
        print("\nGenerated files:")
        print("  1. sdn_ddos_complete.csv - Full processed dataset")
        print("  2. sdn_ddos_train.csv - Training set")
        print("  3. sdn_ddos_test.csv - Test set")
        print("\nYou can now use these files to train your ML models!")
        print("="*60 + "\n")
        
    except Exception as e:
        print(f"\nERROR: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()
