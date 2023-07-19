import pandas as pd
from sklearn.metrics import mean_absolute_error
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeRegressor
from sklearn.ensemble import RandomForestClassifier


# Path of the file to read
dataset_path = '../dataset_phishing.csv'

phishing_data = pd.read_csv(dataset_path)

phishing_data.describe()

# Create target object
y = phishing_data['status']

# Create X
features = ['length_url', 'length_hostname', 'ip', 'nb_www', 'prefix_suffix', 'empty_title', 'domain_in_title', 'domain_age', 'google_index', 'page_rank']
X = phishing_data[features]

# Split into validation and training data
train_X, val_X, train_y, val_y = train_test_split(X, y, test_size=0.3, random_state=1)

# Specify Model
detection_model = DecisionTreeRegressor(random_state=1)
# Fit Model
detection_model.fit(train_X, train_y)

# Make validation predictions 
val_predictions = detection_model.predict(val_X)

print(val_predictions.head())