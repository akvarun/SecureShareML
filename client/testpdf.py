from pandas import read_csv
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from sklearn.metrics import confusion_matrix
from feature_extraction import feature_extraction

def testpdf(filepath):
    #train the model
    df = read_csv('./pdfdataset_n.csv')
    X = df.iloc[:, 0: 21]
    y = df.iloc[:, 21]
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3)
    clf = RandomForestClassifier()
    clf.fit(X_train.values, y_train.values)
    # y_pred = clf.predict(X_test)
    # acs = accuracy_score(y_test, y_pred)
    # cm = confusion_matrix(y_test, y_pred)

    features = feature_extraction(filepath)
    #print(features)
    result = clf.predict(features)
    return(result)

